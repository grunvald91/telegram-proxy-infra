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
import socket
import ssl
import subprocess
import time

from meta_v15_receive_window import nft_rules,verify_queue_exemption
from meta_v23_ru_firsthop_preview import RU_EDGE,WG_BACKEND,RU_INTERFACE,TEST_PORT
from meta_v15_receive_window import HOSTS

ROOT=Path("/var/lib/mneby-meta-v26-ru")
STAGE=Path("/usr/local/libexec/mneby-meta-v26")
UNIT="mneby-meta-v26-ru-watchdog"
WORKER="mneby-meta-v26-ru-window"
TABLE="mneby_meta_v26_ru"
FIREWALL_CHAIN="ufw-user-input"
FIREWALL_COMMENT="mneby-meta-v26-scoped-tcp18443"
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
    if value=="all":return value
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

def firewall_args(peer):
    # Even for shared mode, only traffic DNATed from our own HTTPS 443 may
    # enter the experimental listener. Unrelated direct TCP/18443 is denied.
    peer=checked_peer(peer)
    selector=(["-m","conntrack","--ctstate","DNAT",
               "--ctorigdst",RU_EDGE,"--ctorigdstport","443"]
              if peer=="all" else ["-s",peer+"/32"])
    return selector+["-d",RU_EDGE+"/32","-p","tcp",
                    "--dport",str(TEST_PORT),"-m","comment",
                    "--comment",FIREWALL_COMMENT,"-j","ACCEPT"]

def firewall_present(peer):
    result=cmd(["iptables","-w","5","-C",FIREWALL_CHAIN,*firewall_args(peer)],
               timeout=10,check=False)
    if result.returncode not in (0,1):
        raise RuntimeError("unable to inspect scoped firewall rule")
    return result.returncode==0

def firewall_install(peer):
    if firewall_present(peer):
        raise RuntimeError("owned firewall rule already present before start")
    cmd(["iptables","-w","5","-I",FIREWALL_CHAIN,"1",*firewall_args(peer)],timeout=12)
    if not firewall_present(peer):
        raise RuntimeError("scoped TCP18443 firewall rule installation not verified")

def firewall_remove(peer):
    if firewall_present(peer):
        cmd(["iptables","-w","5","-D",FIREWALL_CHAIN,*firewall_args(peer)],timeout=12)
    if firewall_present(peer):
        raise RuntimeError("scoped TCP18443 firewall rule remains after rollback")

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

def read_evidence(*,required=True):
    path=ROOT/"evidence.json"
    if not path.is_file():
        if required:raise RuntimeError("RU packet evidence missing")
        return {}
    return json.loads(path.read_text())

def evidence_ready():
    from meta_v31_sni_evidence import validate_report
    try:
        report=read_evidence()
        validate_report(report)
        pid=int(cmd(["systemctl","show","-P","MainPID",WORKER+".service"],timeout=4).stdout)
        return report["worker_pid"]==pid and report.get("final") is False
    except (OSError,ValueError,RuntimeError):return False

def verify_tls_path(hosts=None):
    """Verify the ACTUAL private WG:443 -> active DE SNI map -> Meta path.

    This originates on RU, so it verifies the backend half, not the phone's
    access network. Ingress SNI segmentation is measured separately by PCAP.
    """
    from concurrent.futures import ThreadPoolExecutor
    hosts=tuple(sorted(HOSTS) if hosts is None else hosts)
    if not hosts or not set(hosts)<=HOSTS:raise ValueError("unapproved TLS probe hosts")
    routes=json.loads(cmd(["ip","-j","route","get",WG_BACKEND],timeout=5).stdout)
    if not routes or routes[0].get("dev")!="tg-relay":
        raise RuntimeError("live Meta backend left the private WireGuard route")
    def probe(host):
        with socket.create_connection((WG_BACKEND,443),timeout=4) as raw:
            raw.settimeout(4)
            with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
                if not tls.getpeercert():raise RuntimeError("WG origin certificate missing")
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(probe,hosts))
    return len(hosts)

def verify_non_meta_fallback():
    """RU must reach its original public :443 from the receiver itself.

    An ss listener alone is insufficient: a daemon can bind only loopback
    while non-Meta traffic is forwarded to RU_EDGE:443 by the test proxy.
    This TCP-only probe does not assert any hostname-specific TLS service.
    """
    try:
        with socket.create_connection((RU_EDGE, 443), timeout=4):
            pass
    except OSError as exc:
        raise RuntimeError("RU own public HTTPS fallback is unreachable") from exc


def baseline(peer):
    cmd(["tcpdump","--version"],timeout=5)
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
    verify_non_meta_fallback()
    if cmd(["ss","-H","-lnt","sport","=",":"+str(TEST_PORT)]).stdout.strip():
        raise RuntimeError("RU dedicated test listener occupied")
    if ROOT.exists() or table_exists():
        raise RuntimeError("prior RU experiment state exists")
    for name in (UNIT+".timer",WORKER+".service",
                 "mneby-meta-v15-proxy.service","mneby-meta-v15-cleanup.timer"):
        if active(name):raise RuntimeError("prior experimental service active")
    verify_queue_exemption(json.loads(cmd(["nft","-j","list","ruleset"]).stdout))
    # The DNAT target port, not public 443, is seen by UFW's input chain.
    # Verify the chain exists and our exact owned rule is not orphaned.
    cmd(["iptables","-w","5","-S",FIREWALL_CHAIN],timeout=10)
    if firewall_present(peer):
        raise RuntimeError("previous scoped firewall rule was not cleaned up")
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
    # Revoke test ingress even if worker shutdown later fails. A pending
    # marker is persisted before adding the UFW exception, so a crash cannot
    # orphan the allow rule without the independent same-boot cleanup timer.
    try:
        marker=ROOT/"firewall-pending"
        if marker.is_file():
            firewall_remove((ROOT/"peer").read_text().strip())
            marker.unlink()
    except Exception:errors.append("firewall_remove")
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
                 # Signal Python first so it can stop tcpdump with SIGINT,
                 # drain PCAP and save final counters before cgroup teardown.
                 "--property=KillMode=mixed","--property=TimeoutStopSec=15s",
                 "/usr/bin/python3","-u",str(STAGE/"meta_v15_receive_window.py"),
                 "--peer",peer,"--edge",RU_EDGE,"--port",str(TEST_PORT),
                 "--backend-address",WG_BACKEND,
                 "--non-meta-backend-address",RU_EDGE,
                 "--evidence-file",str(ROOT/"evidence.json"),
                 "--max-lifetime",str(WORKER_SECONDS)])
            for i in range(80):
                if ready_worker() and evidence_ready():break
                time.sleep(.1)
            else:raise RuntimeError("owned RU receiver did not listen")
            # Persist recovery intent before making the UFW exception. The
            # 2400-second independent watchdog was armed before this point.
            fd=os.open(ROOT/"firewall-pending",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,"w") as f:
                f.write(peer+"\n");f.flush();os.fsync(f.fileno())
            firewall_install(peer)
            # This one-peer rule also catches other HTTPS to the same RU IP:
            # fallback routing happens after the first ClientHello arrives.
            cmd(["nft","-f","-"],input=rules)
            if not table_exists():raise RuntimeError("RU nft canary table not installed")
            # Refuse to publish phone DNS until every staged exact hostname
            # completes a certificate-verified handshake via the real WG443.
            verified=verify_tls_path()
        except BaseException:
            _rollback_locked()
            raise
    print("meta_v26_ru_peer_receive_window_ready=true",flush=True)
    print("meta_v26_ru_wg_backend_fixed=true",flush=True)
    print("meta_v26_ru_other_https_fallback_fixed=true",flush=True)
    print("meta_v26_ru_same_boot_cleanup_armed=true",flush=True)
    print("meta_v26_ru_firewall_scoped=true",flush=True)
    print("meta_v26_ru_wg_tls_verified_hosts="+str(verified),flush=True)

def reset():
    """Remove saved state only after nft removal and worker termination."""
    import shutil
    if not ROOT.is_dir():return
    with locked():
        _rollback_locked()
        if active(UNIT+".timer"):
            cmd(["systemctl","stop",UNIT+".timer"],timeout=12)
        if active(UNIT+".timer") or table_exists() or ready_worker() or (ROOT/"firewall-pending").exists():
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
        print("meta_v26_ru_firewall_scoped="+str(
            (ROOT/"firewall-pending").is_file() and
            firewall_present((ROOT/"peer").read_text().strip())).lower(),flush=True)
        print("meta_v26_ru_evidence_ready="+str(evidence_ready()).lower(),flush=True)
        verify_tls_path(("i.instagram.com","iglite-z.instagram.com"))
        print("meta_v26_ru_wg_tls=PASS",flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("start","rollback","status","reset","evidence"))
    p.add_argument("--peer")
    args=p.parse_args()
    if args.mode=="start":
        if not args.peer:p.error("RU start requires --peer")
        start(args.peer)
    elif args.mode=="rollback":rollback()
    elif args.mode=="reset":reset()
    elif args.mode=="evidence":print(json.dumps(read_evidence(required=False),sort_keys=True),flush=True)
    else:status()
