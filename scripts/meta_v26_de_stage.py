#!/usr/bin/env python3
"""Independent timed DE Nginx+source-view DNS stage with guarded recovery.

Commands: stage --peer, enable-dns, rollback, status. No global kernel writes.
Requires explicit owner opt-in, persistent owned stage and same-boot timer.
The remote orchestrator must run DE stage -> RU start -> DE enable-dns.
"""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import re
import subprocess
import time

import mnebydns_iglite_wifi_multi_meta_v10_w20 as base
from meta_v23_ru_firsthop_preview import HOSTS, load_renderer
from meta_v25_source_view import render, source_peer

ROOT=Path("/var/lib/mneby-meta-v26-de")
STAGE=Path("/usr/local/libexec/mneby-meta-v26")
UNIT="mneby-meta-v26-de-watchdog"
LIVE_NGINX=Path("/etc/nginx/nginx.conf")
LIVE_DNS=Path("/opt/mnebydns-dot/Corefile")
EDGE="89.125.90.101"
CLEANUP_SECONDS=2400
CLIENT_SECONDS=1800

def cmd(argv,*,timeout=28,check=True):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(argv[0]+" failed with exit="+str(p.returncode))
    return p

def file(name):return ROOT/name

def flag():
    if (os.geteuid()!=0 or Path(__file__).resolve().parent!=STAGE or
            os.environ.get("MNEBY_META_V26_APPROVED")!="YES"):
        raise RuntimeError("explicit approval and reviewed persistent DE stage required")

def active(service):return cmd(["systemctl","is-active","--quiet",service],check=False).returncode==0

def write(name,content):
    base.write_exclusive(file(name),content)
    base.fsync_directory(ROOT)

def replace(path,data):base.atomic_replace(path,data)

def lock():
    import contextlib
    @contextlib.contextmanager
    def _locked():
        ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=os.open(file("lock"),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN)
            os.close(fd)
    return _locked()

def snapshot():
    for key in ("nginx","dns"):
        for suffix in ("original","candidate"):
            if not file(key+"."+suffix).is_file():
                raise RuntimeError("required DE checkpoint missing")
    return {
        "nginx":(LIVE_NGINX,file("nginx.original").read_bytes(),file("nginx.candidate").read_bytes()),
        "dns":(LIVE_DNS,file("dns.original").read_bytes(),file("dns.candidate").read_bytes()),
    }

def guards():
    if not active("nginx.service") or not active("mnebydns-dot.service"):
        raise RuntimeError("DE production baseline service inactive")
    ip=cmd(["ip","-4","-o","addr","show"]).stdout
    if not re.search(r"\s89[.]125[.]90[.]101/",ip):
        raise RuntimeError("not owner DE public edge")
    for name in ("mneby-meta-v15-cleanup.timer","mneby-meta-v15-route-watchdog.timer"):
        if active(name):raise RuntimeError("another Meta experiment active")
    if cmd(["nft","list","table","inet","mneby_meta_v15"],check=False).returncode==0:
        raise RuntimeError("legacy Meta redirect not removed")

def compiled_plugins():
    pid=int(cmd(["systemctl","show","-P","MainPID","mnebydns-dot.service"]).stdout.strip())
    if pid<=0:raise RuntimeError("DoT service has no running binary")
    return cmd(["/proc/"+str(pid)+"/exe","-plugins"],timeout=8).stdout

def stage(peer):
    flag()
    peer=source_peer(peer)
    if ROOT.exists():raise RuntimeError("prior DE checkpoint exists; do not overwrite")
    guards()
    if active(UNIT+".timer"):raise RuntimeError("previous DE recovery active")
    stable=base.CHECKPOINT_CURRENT
    if stable.is_file():
        checkpoint=Path(stable.read_text().strip())
        for filename,live in (("dns.stable",LIVE_DNS),("nginx.stable",LIVE_NGINX)):
            prior=checkpoint/filename
            if not prior.is_file() or prior.read_bytes()!=live.read_bytes():
                raise RuntimeError("DE live file differs from stable checkpoint")
    org_ng=LIVE_NGINX.read_bytes()
    org_dns=LIVE_DNS.read_bytes()
    owner=load_renderer()
    # Verify every pinned origin once. Re-resolving between preflight and
    # rendering could silently change the route after the TLS check.
    verified={host:owner.origin_ip(host) for host in HOSTS}
    next_ng=org_ng.decode()
    for host in HOSTS:
        next_ng=owner.nginx_add(next_ng,host,verified[host])
    reversed_ng=next_ng
    for host in reversed(HOSTS):
        reversed_ng=owner.nginx_remove(reversed_ng,host)
    if reversed_ng!=org_ng.decode():
        raise AssertionError("Nginx routes are not reversible")
    plan=render(corefile=org_dns.decode(),phone_ip=peer,
                compiled_plugins=compiled_plugins())
    plan.verify_rollback()
    with lock():
        write("nginx.original",org_ng)
        write("dns.original",org_dns)
        write("nginx.candidate",next_ng.encode())
        write("dns.candidate",plan.candidate.encode())
        write("peer",peer.encode("ascii"))
        cmd(["nginx","-t","-c",str(file("nginx.candidate"))],timeout=20)
        cmd(["systemd-run","--quiet","--collect","--unit",UNIT,
             "--on-active="+str(CLEANUP_SECONDS)+"s",
             "/usr/bin/python3",str(Path(__file__).resolve()),"rollback"])
        if not active(UNIT+".timer"):
            raise RuntimeError("independent DE rollback was not armed")
        write("armed",b"armed\n")
        try:
            replace(LIVE_NGINX,next_ng.encode())
            cmd(["nginx","-t"],timeout=20)
            cmd(["systemctl","reload","nginx.service"],timeout=25)
        except BaseException:
            # Cannot re-enter lock: recover directly with checked ownership.
            _rollback_locked()
            raise
    print("meta_v26_de_sni_routes_ready=true",flush=True)
    print("meta_v26_de_dns_not_activated=true",flush=True)
    print("meta_v26_de_same_boot_cleanup_armed=true",flush=True)

def enable_dns():
    flag()
    if not file("armed").is_file():raise RuntimeError("DE stage not prepared")
    with lock():
        files=snapshot()
        if not active(UNIT+".timer"):
            raise RuntimeError("DE independent timer expired before activation")
        if LIVE_NGINX.read_bytes()!=files["nginx"][2]:
            raise RuntimeError("DE SNI route missing or changed")
        if LIVE_DNS.read_bytes()!=files["dns"][1]:
            raise RuntimeError("DNS baseline changed before activation")
        replace(LIVE_DNS,files["dns"][2])
        try:cmd(["systemctl","restart","mnebydns-dot.service"],timeout=30)
        except BaseException:
            _rollback_locked()
            raise
        if not active("mnebydns-dot.service") or LIVE_DNS.read_bytes()!=files["dns"][2]:
            _rollback_locked()
            raise RuntimeError("DE DoT activation not verified")
    print("meta_v26_de_source_scoped_dns_ready=true",flush=True)

def _rollback_locked():
    if not file("armed").is_file():
        print("meta_v26_de_rollback=NO_MUTATION",flush=True)
        return
    files=snapshot()
    # Verify both files before modifying either: never erase concurrent edits.
    for key,(live,original,candidate) in files.items():
        if live.read_bytes() not in (original,candidate):
            raise RuntimeError("external DE "+key+" configuration drift")
    changed=[]
    for key in ("dns","nginx"):
        live,original,_=files[key]
        if live.read_bytes()!=original:
            replace(live,original)
            changed.append(key)
    errors=[]
    # Restore both independently even if the first service fails. Stopping at
    # a failed DNS restart would leave Nginx running its experimental SNI map.
    if "dns" in changed:
        try:cmd(["systemctl","restart","mnebydns-dot.service"],timeout=30)
        except (OSError,subprocess.TimeoutExpired,RuntimeError):
            errors.append("dns_restart")
    if "nginx" in changed:
        try:
            cmd(["nginx","-t"],timeout=20)
            cmd(["systemctl","reload","nginx.service"],timeout=25)
        except (OSError,subprocess.TimeoutExpired,RuntimeError):
            errors.append("nginx_restore")
    try:
        if not active("nginx.service") or not active("mnebydns-dot.service"):
            errors.append("baseline_service_inactive")
    except (OSError,subprocess.TimeoutExpired,RuntimeError):
        errors.append("baseline_status_unavailable")
    if any(live.read_bytes()!=original for live,original,_ in files.values()):
        errors.append("config_restoration_mismatch")
    if errors:
        raise RuntimeError("DE rollback incomplete: "+",".join(errors))
    print("meta_v26_de_cleanup=VERIFIED",flush=True)

def rollback():
    if not ROOT.is_dir():return
    with lock():_rollback_locked()

def reset():
    """Forget verified restored state, including interrupted pre-arm staging.

    stage() never modifies production before writing 'armed'. A failure while
    writing the checkpoints or checking Nginx therefore leaves an incomplete
    directory that must be removable without requiring nonexistent snapshots.
    """
    import shutil
    if not ROOT.is_dir():return
    with lock():
        armed=file("armed").is_file()
        if armed:
            _rollback_locked()
        else:
            # No production edits are allowed before the durable armed marker.
            # Verify every original checkpoint that was successfully written.
            for key,live in (("nginx",LIVE_NGINX),("dns",LIVE_DNS)):
                prior=file(key+".original")
                if prior.is_file() and live.read_bytes()!=prior.read_bytes():
                    raise RuntimeError("DE unarmed reset rejected: "+key+" baseline drift")
            if not active("nginx.service") or not active("mnebydns-dot.service"):
                raise RuntimeError("DE unarmed reset rejected: baseline service inactive")
        if active(UNIT+".timer"):
            cmd(["systemctl","stop",UNIT+".timer"],timeout=12)
        if active(UNIT+".timer"):
            raise RuntimeError("DE watchdog did not stop")
        if armed:
            for live,original,_candidate in snapshot().values():
                if live.read_bytes()!=original:
                    raise RuntimeError("DE reset rejected: route not restored")
    shutil.rmtree(ROOT)
    print("meta_v26_de_state_reset=VERIFIED",flush=True)

def status():
    if not ROOT.is_dir():
        print("meta_v26_de_status=NO_STATE",flush=True);return
    with lock():
        files=snapshot()
        for key,(live,original,candidate) in files.items():
            now=live.read_bytes()
            state="BASELINE" if now==original else ("EXPERIMENT" if now==candidate else "DRIFT")
            print("meta_v26_de_"+key+"_state="+state,flush=True)
        print("meta_v26_de_timer_active="+str(active(UNIT+".timer")).lower(),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("stage","enable-dns","rollback","status","reset"))
    p.add_argument("--peer")
    args=p.parse_args()
    if args.mode=="stage":
        if not args.peer:p.error("stage needs --peer")
        stage(args.peer)
    elif args.mode=="enable-dns":enable_dns()
    elif args.mode=="rollback":rollback()
    elif args.mode=="reset":reset()
    else:status()
