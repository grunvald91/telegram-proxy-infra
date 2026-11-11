#!/usr/bin/env python3
"""Owner-requested 900s IPv4 phone canary, explicit peer required.

Reuse the reviewed exact-host v11 route/restore engine and add a separately
supervised receiver-window proxy. No global sysctl or queue210 rule changes.
"""
import argparse
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import threading
import time

import mnebydns_iglite_route_only_v11 as route
from meta_v15_receive_window import nft_rules,verify_queue_exemption

STATE=Path("/var/lib/mneby-meta-v15-controller")
STAGE=Path("/usr/local/libexec/mneby-meta-v15")
UNIT="mneby-meta-v15-cleanup"
WORKER="mneby-meta-v15-proxy"
TABLE="mneby_meta_v15"
EDGE="89.125.90.101"
PORT=18443

route.base.ROOT=Path("/var/lib/mneby-meta-v15-routes")
route.base.UNIT="mneby-meta-v15-route-watchdog"
route.base.TABLE="mneby_meta_v15_unexpected_global"
route.base.PERSISTENT_STAGE=STAGE
route.ROLLBACK_SCRIPT=Path(__file__).resolve()
route.TRANSPORT_LABEL="V15_PEER_WINDOW8_NO_GLOBAL_SYSCTL"
_THREAD_LOCK=threading.RLock()
_LOCK_DEPTH=threading.local()
_CONFIG_ROLLBACK=route.rollback


def command(*args,**kwargs):return route.base.command(*args,**kwargs)

@contextmanager
def state_lock():
    """Serialize in-process restoration and both independent watchdogs."""
    with _THREAD_LOCK:
        depth=getattr(_LOCK_DEPTH,"value",0)
        fd=None
        if depth==0:
            fd=os.open(STATE/"lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:fcntl.flock(fd,fcntl.LOCK_EX)
            except BaseException:
                os.close(fd)
                raise
        _LOCK_DEPTH.value=depth+1
        try:yield
        finally:
            _LOCK_DEPTH.value=depth
            if fd is not None:
                fcntl.flock(fd,fcntl.LOCK_UN)
                os.close(fd)

def config_rollback():
    if not STATE.is_dir():return _CONFIG_ROLLBACK()
    with state_lock():return _CONFIG_ROLLBACK()

route.rollback=config_rollback

def table_exists():
    # A failed nft command is not evidence that a table is absent.
    result=json.loads(command(["nft","-j","list","tables"]).stdout)
    return any(item.get("table",{}).get("family")=="inet" and
               item.get("table",{}).get("name")==TABLE
               for item in result["nftables"])

def worker_state():
    text=command(["systemctl","show",WORKER+".service",
                  "-p","LoadState","-p","ActiveState","-p","SubState","-p","MainPID"],
                 timeout=3).stdout
    info=dict(line.split("=",1) for line in text.splitlines() if "=" in line)
    if not all(key in info for key in ("LoadState","ActiveState","SubState","MainPID")):
        raise RuntimeError("incomplete worker state")
    info["MainPID"]=int(info["MainPID"])
    return info

def worker_ready():
    info=worker_state()
    if (info["LoadState"]!="loaded" or info["ActiveState"]!="active" or
        info["SubState"]!="running" or info["MainPID"]<=0):return False
    listeners=command(["ss","-H","-lntp","sport","=",":"+str(PORT)],timeout=3).stdout
    return any(re.search(r"\b"+re.escape(EDGE)+":"+str(PORT)+r"\s",line) and
               re.search(r"\bpid="+str(info["MainPID"])+r"[,)]",line)
               for line in listeners.splitlines())

def check_live():
    if (STATE/"cleanup-started").exists():
        raise RuntimeError("v15 cleanup has started; trial aborted")
    if not worker_ready():raise RuntimeError("owned v15 worker/listener not healthy")

@contextmanager
def mutation_guard():
    with state_lock():
        check_live()
        yield

def wait_trial(seconds):
    deadline=time.monotonic()+seconds
    while True:
        check_live()
        remaining=deadline-time.monotonic()
        if remaining<=0:return
        time.sleep(min(2,remaining))

route.MUTATION_GUARD=mutation_guard
route.LIVE_CHECK=check_live
route.TRIAL_WAIT=wait_trial

def cleanup():
    if not (STATE/"armed").is_file():return
    with state_lock():return _cleanup_locked()

def _cleanup_locked():
    marker=STATE/"cleanup-started"
    if not marker.exists():
        route.base.write_exclusive(marker,b"cleanup\n")
        route.base.fsync_directory(STATE)
    errors=[]
    # Remove redirection first, then close only the dedicated worker sockets.
    try:
        if table_exists():
            command(["nft","delete","table","inet",TABLE])
    except Exception:errors.append("nft")
    try:command(["systemctl","stop",WORKER+".service"],timeout=20,check=False)
    except Exception:errors.append("worker")
    try:route.rollback()
    except Exception:errors.append("routes")
    try:
        if table_exists():errors.append("nft_still_present")
    except Exception:errors.append("nft_verification_unavailable")
    try:
        info=worker_state()
        if info["MainPID"]!=0 or info["ActiveState"] not in ("inactive","failed"):
            errors.append("worker_still_active")
    except Exception:errors.append("worker_verification_unavailable")
    if errors:raise RuntimeError("v15 cleanup failed: "+",".join(errors))
    print("meta_v15_cleanup=VERIFIED",flush=True)


def live(peer):
    peer=str(ipaddress.IPv4Address(peer))
    if not ipaddress.IPv4Address(peer).is_global or peer==EDGE:
        raise ValueError("identified test-phone public IPv4 required")
    if os.geteuid()!=0 or Path(__file__).resolve().parent!=STAGE:
        raise RuntimeError("requires root and persistent reviewed stage")
    if os.environ.get("MNEBY_META_V15_APPROVED")!="YES":
        raise RuntimeError("explicit canary flag required")
    for key in ("MNEBY_IGLITE_LIVE_APPROVED","MNEBY_IGLITE_TEMPORARY_ONLY_APPROVED",
                "MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED"):
        os.environ[key]="YES"
    route.check_retired_v10()
    route.base.baseline()
    for unit in (UNIT,WORKER,"mneby-ig-lite-route-only-20261111-v11"):
        for suffix in (".timer",".service"):
            if command(["systemctl","is-active","--quiet",unit+suffix],check=False).returncode==0:
                raise RuntimeError("another experiment unit active")
    if STATE.exists() or table_exists():
        raise RuntimeError("prior v15 state exists; refuse duplicate")
    # Verify the actual live queue guard before relying on socket SO_MARK.
    ruleset=json.loads(command(["nft","-j","list","ruleset"]).stdout)
    verify_queue_exemption(ruleset)
    rules=nft_rules(EDGE,peer,port=PORT)
    command(["nft","--check","-f","-"],input=rules)
    if command(["ss","-H","-lnt","sport", "=", ":"+str(PORT)]).stdout.strip():
        raise RuntimeError("dedicated port occupied")
    STATE.mkdir(mode=0o700)
    owner=os.environ.get("MNEBY_META_V15_RUN_ID","manual")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}",owner):
        raise ValueError("invalid run identity")
    route.base.write_exclusive(STATE/"owner",owner.encode("ascii"))
    route.base.write_exclusive(STATE/"peer",peer.encode("ascii"))
    route.base.write_exclusive(STATE/"armed",b"armed\n")
    route.base.fsync_directory(STATE)
    route.base.fsync_directory(STATE.parent)
    old_handlers={sig:signal.signal(sig,route.interrupted)
                  for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    try:
        # Exists independently of SSH and the Python controller. The inner
        # v11 timer also points back to this full cleanup entrypoint.
        route.EXTERNAL_DEADLINE=time.monotonic()+1500
        command(["systemd-run","--quiet","--collect","--unit",UNIT,
                 "--on-active=1500s","/usr/bin/python3",str(Path(__file__).resolve()),"rollback"])
        if command(["systemctl","is-active","--quiet",UNIT+".timer"],check=False).returncode:
            raise RuntimeError("independent full cleanup timer not armed")
        command(["systemd-run","--quiet","--collect","--unit",WORKER,
                 "--property=RuntimeMaxSec=1500","--property=KillMode=control-group",
                 "/usr/bin/python3","-u",str(STAGE/"meta_v15_receive_window.py"),
                 "--peer",peer,"--edge",EDGE,"--port",str(PORT)])
        startup_deadline=time.monotonic()+8
        while time.monotonic()<startup_deadline:
            if worker_ready():break
            time.sleep(.1)
        else:raise RuntimeError("dedicated proxy not listening")
        with mutation_guard():command(["nft","-f","-"],input=rules)
        route.CAPTURE_PEER=peer
        print("meta_v15_mechanism=PER_SOCKET_SCALE0_WINDOW8_UNTIL_SNI",flush=True)
        print("meta_v15_scope=ONE_IPV4_PEER_TCP443",flush=True)
        print("meta_v15_phone_identity=NAT_PEER_ONLY_NOT_DEVICE_PROOF",flush=True)
        route.live()
    finally:
        for sig in old_handlers:signal.signal(sig,signal.SIG_IGN)
        try:cleanup()
        finally:
            for sig,handler in old_handlers.items():signal.signal(sig,handler)
    print("meta_v15_android_bypass=REQUIRES_PHONE_RESULT",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=("live","rollback"))
    parser.add_argument("--peer")
    args=parser.parse_args()
    if args.mode=="rollback":cleanup()
    elif args.peer:live(args.peer)
    else:parser.error("live requires --peer (test-phone public IPv4)")
