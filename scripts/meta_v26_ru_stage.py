#!/usr/bin/env python3
"""RU188 receiver canary: one public client, 18443, WG backend, timed rollback.

Commands: start --peer; rollback; status. Does not write DNS or Nginx.
The real public :443 remains owned by the existing RU service: an exact-source
temporary nft DNAT precedes only that client's TCP connections. Other SNI
falls back to the RU HTTPS listener (with a temporary small initial window).
"""
from __future__ import annotations
import argparse
import fcntl
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time

from meta_v15_receive_window import nft_rules,verify_queue_exemption
from meta_v23_ru_firsthop_preview import RU_EDGE,WG_BACKEND,RU_INTERFACE,TEST_PORT

ROOT=Path("/var/lib/mneby-meta-v26-ru")
STAGE=Path("/usr/local/libexec/mneby-meta-v26")
UNIT="mneby-meta-v26-ru-watchdog"
WORKER="mneby-meta-v26-ru-window"
TABLE="mneby_meta_v26_ru"
CLEANUP_SECONDS=2400
WORKER_SECONDS=2700

def cmd(argv,*,input=None,timeout=20,check=True):
    p=subprocess.run(argv,input=input,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(argv[0]+" exit="+str(p.returncode))
    return p

def active(name):
    return cmd(["systemctl","is-active","--quiet",name],check=False).returncode==0

def checked_peer(value):
    parsed=ipaddress.IPv4Address(value)
    if not parsed.is_global or str(parsed) in (RU_EDGE,"89.125.90.101"):
        raise ValueError("one distinct public client IPv4 required")
    return str(parsed)

def owner_flag():
    if os.geteuid()!=0 or Path(__file__).resolve().parent!=STAGE:
        raise RuntimeError("root and reviewed RU persistent stage required")
    if os.environ.get("MNEBY_META_V26_APPROVED")!="YES":
        raise RuntimeError("explicit owner approval required")

def table_exists():
    rules=json.loads(cmd(["nft","-j","list","tables"],timeout=10).stdout)
    return any(v.get("table",{}).get("family")=="inet" and
               v.get("table",{}).get("name")==TABLE
               for v in rules.get("nftables",[]))

@contextmanager
def locked():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(ROOT/"lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)

def ready_worker():
    info=cmd(["systemctl","show",WORKER+".service",
              "-p","MainPID","-p","ActiveState","-p","SubState"],timeout=5).stdout
    vals=dict(x.split("=",1) for x in info.splitlines() if "=" in x)
    pid=int(vals.get("MainPID","0"))
    if vals.get("ActiveState")!="active" or vals.get("SubState")!="running" or pid<=0:
        return False
    ss=cmd(["ss","-H","-lntp","sport","=",":"+str(TEST_PORT)],timeout=6).stdout
    return any(RU_EDGE+":"+str(TEST_PORT) in x and
               re.search(r"\bpid="+str(pid)+r"[,)]",x)
               for x in ss.splitlines())

def baseline(peer):
    if not active("wg-quick@tg-relay.service"):
        raise RuntimeError("RU private WireGuard service inactive")
    route=cmd(["ip","-j","route","get",WG_BACKEND]).stdout
    obj=json.loads(route)
    if not obj or obj[0].get("dev")!="tg-relay":
        raise RuntimeError("private DE WireGuard route absent")
    ips=cmd(["ip","-4","-o","addr","show","dev",RU_INTERFACE]).stdout
    if not re.search(r"\s188[.]120[.]254[.]223/",ips):
        raise RuntimeError("RU owner public IP missing on ens3")
    if cmd(["sysctl","-n","net.ipv4.tcp_window_scaling"]).stdout.strip()!="1":
        raise RuntimeError("normal TCP window scaling unavailable")
    if not cmd(["ss","-H","-lnt","sport","=",":443"]).stdout.strip():
        raise RuntimeError("RU original HTTPS backend is not listening")
    if cmd(["ss","-H","-lnt","sport","=",":"+str(TEST_PORT)]).stdout.strip():
        raise RuntimeError("RU dedicated test listener occupied")
    if ROOT.exists() or table_exists():
        raise RuntimeError("prior RU experiment state exists")
    for name in (UNIT+".timer",WORKER+".service",
                 "mneby-meta-v15-proxy.service","mneby-meta-v15-cleanup.timer"):
        if active(name):raise RuntimeError("prior experimental service active")
    verify_queue_exemption(json.loads(cmd(["nft","-j","list","ruleset"]).stdout))
    rules=nft_rules(RU_EDGE,peer,port=TEST_PORT,interface=RU_INTERFACE,table=TABLE)
    # Check parsing/chain collisions without mutating nftables.
    p=cmd(["nft","--check","-f","-"],input=rules)
    return rules

def _rollback_locked():
    if not (ROOT/"armed").is_file():
        print("meta_v26_ru_cleanup=NO_MUTATION",flush=True)
        return
    errors=[]
    try:
        if table_exists():cmd(["nft","delete","table","inet",TABLE])
    except Exception:errors.append("nft_remove")
    try:cmd(["systemctl","stop",WORKER+".service"],timeout=15,check=False)
    except Exception:errors.append("worker_stop")
    try:
        if table_exists():errors.append("nft_still_present")
    except Exception:errors.append("nft_state_unavailable")
    try:
        state=cmd(["systemctl","show",WORKER+".service",
                   "-p","MainPID","-p","ActiveState"],timeout=5).stdout
        pairs=dict(x.split("=",1) for x in state.splitlines() if "=" in x)
        if int(pairs.get("MainPID","-1"))!=0 or pairs.get("ActiveState") not in ("inactive","failed"):
            errors.append("worker_still_active")
    except Exception:errors.append("worker_state_unavailable")
    if errors:raise RuntimeError("RU recovery incomplete: "+",".join(errors))
    print("meta_v26_ru_cleanup=VERIFIED",flush=True)

def rollback():
    if not ROOT.exists():return
    with locked():_rollback_locked()

def start(peer):
    owner_flag()
    peer=checked_peer(peer)
    rules=baseline(peer)
    with locked():
        # Existing baseline was checked before the state dir was created.
        fd=os.open(ROOT/"peer",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"w") as target:
            target.write(peer)
            target.flush()
            os.fsync(target.fileno())
        cmd(["systemd-run","--quiet","--collect","--unit",UNIT,
             "--on-active="+str(CLEANUP_SECONDS)+"s","/usr/bin/python3",
             str(Path(__file__).resolve()),"rollback"])
        if not active(UNIT+".timer"):
            raise RuntimeError("RU independent cleanup timer not armed")
        fd=os.open(ROOT/"armed",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"w") as f:
            f.write("armed\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            cmd(["systemd-run","--quiet","--collect","--unit",WORKER,
                 "--property=RuntimeMaxSec="+str(WORKER_SECONDS),
                 "--property=KillMode=control-group",
                 "/usr/bin/python3","-u",str(STAGE/"meta_v15_receive_window.py"),
                 "--peer",peer,"--edge",RU_EDGE,"--port",str(TEST_PORT),
                 "--backend-address",WG_BACKEND,
                 "--non-meta-backend-address",RU_EDGE,
                 "--max-lifetime",str(WORKER_SECONDS)])
            for i in range(80):
                if ready_worker():break
                time.sleep(.1)
            else:raise RuntimeError("owned RU receiver did not listen")
            # This one-peer rule also catches other HTTPS to the same RU IP:
            # fallback routing happens after the first ClientHello arrives.
            cmd(["nft","-f","-"],input=rules)
            if not table_exists():raise RuntimeError("RU nft canary table not installed")
        except BaseException:
            _rollback_locked()
            raise
    print("meta_v26_ru_peer_receive_window_ready=true",flush=True)
    print("meta_v26_ru_wg_backend_fixed=true",flush=True)
    print("meta_v26_ru_other_https_fallback_fixed=true",flush=True)
    print("meta_v26_ru_same_boot_cleanup_armed=true",flush=True)

def reset():
    """Remove saved state only after nft removal and worker termination."""
    import shutil
    if not ROOT.is_dir():return
    with locked():
        _rollback_locked()
        if active(UNIT+".timer"):
            cmd(["systemctl","stop",UNIT+".timer"],timeout=12)
        if active(UNIT+".timer") or table_exists() or ready_worker():
            raise RuntimeError("RU reset rejected: experimental route still active")
    shutil.rmtree(ROOT)
    print("meta_v26_ru_state_reset=VERIFIED",flush=True)

def status():
    if not ROOT.exists():
        print("meta_v26_ru_status=NO_STATE",flush=True);return
    with locked():
        print("meta_v26_ru_table_present="+str(table_exists()).lower(),flush=True)
        print("meta_v26_ru_worker_ready="+str(ready_worker()).lower(),flush=True)
        print("meta_v26_ru_timer_active="+str(active(UNIT+".timer")).lower(),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("start","rollback","status","reset"))
    p.add_argument("--peer")
    args=p.parse_args()
    if args.mode=="start":
        if not args.peer:p.error("RU start requires --peer")
        start(args.peer)
    elif args.mode=="rollback":rollback()
    elif args.mode=="reset":reset()
    else:status()
