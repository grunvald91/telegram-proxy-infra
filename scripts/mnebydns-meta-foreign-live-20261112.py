#!/usr/bin/env python3
"""Time-bounded Meta-family trial on existing DE edge, NO SNI modification.

Only invoked explicitly on the foreign VPS with root privileges. Uses three
live-config snapshots, current checkpoint and a persistent systemd timer.
No packet queue/sysctl/WireGuard changes and no permanent promotion.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time

RUNROOT=Path("/opt/mnebydns-meta-foreign")
CHECKROOT=Path("/opt/mnebydns-stable-checkpoints")
CURRENT=CHECKROOT/"current"
LOCK=Path("/run/lock/mnebyvpn-public-route.lock")
LIVE={
    "dns":Path("/opt/mnebydns-dot/Corefile"),
    "nginx":Path("/etc/nginx/nginx.conf"),
    "proxy":Path("/etc/mnebydns-googlepilot/nginx.conf"),
}
SERVICES=("nginx.service","mnebydns-dot.service","mnebydns-googlepilot.service")
FOREIGN="89.125.90.101"
RUN_RE=re.compile(r"[1-9][0-9]{8,12}$")
OWNER_TIMER_PATTERN="mnebydns-owner-rollback-"

def cmd(*args:str, timeout:int=35, output:bool=False) -> str:
    p=subprocess.run(args,check=True,capture_output=True,text=True,timeout=timeout)
    return p.stdout.strip() if output else ""

@contextmanager
def locked():
    with LOCK.open("a+") as fh:
        fcntl.flock(fh,fcntl.LOCK_EX)
        try:yield
        finally:fcntl.flock(fh,fcntl.LOCK_UN)

def verify_checkpoint() -> Path:
    p=Path(CURRENT.read_text().strip())
    if not re.fullmatch(r"/opt/mnebydns-stable-checkpoints/[0-9]+",str(p)):
        raise RuntimeError("Invalid stable checkpoint pointer")
    proc=subprocess.run(["sha256sum","-c","stable-manifest.sha256"],
                        cwd=p,capture_output=True,timeout=12)
    if proc.returncode:raise RuntimeError("Stable manifest mismatch")
    for role,path in LIVE.items():
        if path.read_bytes()!=(p/(role+".stable")).read_bytes():
            raise RuntimeError("Shared stable checkpoint drift: "+role)
    return p

def check_services() -> None:
    for unit in SERVICES:
        cmd("systemctl","is-active","--quiet",unit)
    cmd("nginx","-t")
    for port in (443,853,15449):
        lines=cmd("ss","-H","-lnt",output=True)
        if not any(":"+str(port) in line for line in lines.splitlines()):
            raise RuntimeError("Missing required listener port "+str(port))

def owner_quiescent() -> None:
    # Another exact-host canary can change the three shared configs;
    # block instead of fighting concurrent owner/108-domain operations.
    timers=cmd("systemctl","list-timers","--no-legend",output=True)
    for line in timers.splitlines():
        if OWNER_TIMER_PATTERN in line:
            raise RuntimeError("Owner DNS timer present: defer Meta canary")
    if any(RUNROOT.glob("*/pending")):
        raise RuntimeError("Another Meta canary awaits recovery")

def write_atomically(path:Path, content:bytes) -> None:
    tmp=path.with_name(path.name+".meta-candidate-tmp")
    if tmp.exists():raise RuntimeError("Unexpected staged config exists")
    stat=path.stat()
    with tmp.open("xb") as out:
        out.write(content);out.flush();os.fsync(out.fileno())
    os.chmod(tmp,stat.st_mode & 0o777)
    os.chown(tmp,stat.st_uid,stat.st_gid)
    os.replace(tmp,path)

def renderer(path:Path):
    spec=importlib.util.spec_from_file_location("meta_route",path)
    if not spec or not spec.loader:raise RuntimeError("Missing route renderer")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def dns_query(host:str,kind:int,server:str="127.0.0.1",port:int=18553) -> tuple[int,list[str],int]:
    qname=b"".join(bytes([len(label)])+label.encode() for label in host.split("."))+b"\0"
    ident=os.urandom(2)
    msg=ident+struct.pack("!HHHHH",0x0100,1,0,0,0)+qname+struct.pack("!HH",kind,1)
    def recvall(tls,n):
        ret=b""
        while len(ret)<n:
            c=tls.recv(n-len(ret))
            if not c:raise RuntimeError("Truncated DNS over TLS")
            ret+=c
        return ret
    with socket.create_connection((server,port),timeout=6) as sock:
        sock.settimeout(7)
        with ssl.create_default_context().wrap_socket(sock,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(len(msg).to_bytes(2,"big")+msg)
            size=int.from_bytes(recvall(tls,2),"big")
            if size<12 or size>8192:raise RuntimeError("Invalid DoT size")
            buf=recvall(tls,size)
    if buf[:2]!=ident or buf[4:6]!=b"\0\x01":raise RuntimeError("DoT question mismatch")
    rcode=buf[3]&15
    count=int.from_bytes(buf[6:8],"big")
    def skip_name(pos):
        for i in range(128):
            if pos>=len(buf):raise RuntimeError("Bad DNS wire name")
            n=buf[pos]
            if n&0xc0==0xc0:return pos+2
            if n==0:return pos+1
            pos+=n+1
        raise RuntimeError("Bad DNS name compression")
    pos=skip_name(12)+4
    a=[]
    for _ in range(count):
        pos=skip_name(pos)
        if pos+10>len(buf):raise RuntimeError("Bad RR header")
        typ,cl,ttl,n=struct.unpack_from("!HHIH",buf,pos);pos+=10
        if pos+n>len(buf):raise RuntimeError("Bad RR length")
        if typ==1 and cl==1 and n==4:a.append(socket.inet_ntoa(buf[pos:pos+4]))
        pos+=n
    return rcode,a,count

def test_dns(port=18553):
    for host in ("i.instagram.com","graph.instagram.com","scontent.cdninstagram.com",
                 "www.instagram.com","graph.facebook.com","www.youtube.com",
                 "gemini.google.com","claude.ai","api.telegram.org"):
        rc,ips,n=dns_query(host,1,port=port,server="127.0.0.1" if port==18553 else FOREIGN)
        if rc!=0:raise RuntimeError("DoT error for "+host)
        if host in ("api.telegram.org",):
            if FOREIGN in ips:raise RuntimeError("Ordinary direct DNS polluted")
        elif ips!=[FOREIGN]:
            raise RuntimeError("Incorrect proxy A answer for "+host)
        if host in ("i.instagram.com","www.instagram.com","scontent.cdninstagram.com"):
            for rr in (28,65,64,5):
                rc,ans,n=dns_query(host,rr,port=port,server="127.0.0.1" if port==18553 else FOREIGN)
                if rc!=0 or n!=0 or ans:
                    raise RuntimeError("Meta alternate DNS bypass for "+host)

def validate_candidate_dns(path:Path,backup:Path) -> None:
    original=path.read_text()
    if original.count("tls://.:853 {")!=1 or original.count("    bind "+FOREIGN)!=1:
        raise RuntimeError("Unknown live public CoreDNS listener")
    local=original.replace("tls://.:853 {","tls://.:18553 {",1).replace(
        "    bind "+FOREIGN,"    bind 127.0.0.1",1)
    staged=backup/"dns.loopback"
    staged.write_text(local)
    staged.chmod(0o600)
    log=(backup/"dns.loopback.log").open("w")
    proc=subprocess.Popen(["/opt/mnebydns-dot/coredns","-conf",str(staged)],
                          stdout=log,stderr=subprocess.STDOUT)
    try:
        for attempt in range(40):
            if proc.poll() is not None:
                raise RuntimeError("Candidate CoreDNS failed startup")
            try:
                with socket.create_connection(("127.0.0.1",18553),timeout=.3):
                    break
            except OSError:time.sleep(.15)
        else:raise RuntimeError("Candidate CoreDNS did not listen")
        test_dns()
    finally:
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        log.close()

def local_tls(host:str) -> None:
    # Real TLS origin certificate via existing shared public SNI dispatcher.
    with socket.create_connection(("127.0.0.1",443),timeout=9) as plain:
        plain.settimeout(9)
        with ssl.create_default_context().wrap_socket(plain,server_hostname=host) as tls:
            if not tls.getpeercert():raise RuntimeError("Missing origin certificate "+host)

def write_timer(base:Path,runid:str) -> str:
    deadline=datetime.now(timezone.utc)+timedelta(minutes=35)
    when=deadline.strftime("%Y-%m-%d %H:%M:%S UTC")
    name="mnebydns-meta-foreign-rollback-"+runid
    service=(f"[Unit]\nDescription=Rollback non-promoted Meta family canary {runid}\n"
             "[Service]\nType=oneshot\n"
             f"ExecStart=/usr/bin/python3 {base}/live.py rollback {runid}\n")
    timer=(f"[Unit]\nDescription=Independent Meta family rollback {runid}\n"
           "[Timer]\n"+f"OnCalendar={when}\n"
           "Persistent=true\nAccuracySec=1s\n"
           f"Unit={name}.service\n[Install]\nWantedBy=timers.target\n")
    for ext,body in (("service",service),("timer",timer)):
        path=Path("/etc/systemd/system")/(name+"."+ext)
        if path.exists():raise RuntimeError("Rollback unit collision")
        path.write_text(body)
        path.chmod(0o644)
    cmd("systemctl","daemon-reload")
    cmd("systemctl","enable","--now",name+".timer")
    cmd("systemctl","is-active","--quiet",name+".timer")
    print("meta_rollback_armed_until_utc="+when,flush=True)
    return name

def restore_unlocked(base:Path) -> None:
    if (base/"confirmed").exists():
        print("meta_canary_confirmed_no_rollback=true",flush=True)
        return
    if not (base/"pending").exists():
        print("meta_no_pending_rollback=true",flush=True)
        return
    # Never overwrite a third-party owner-domain deployment.
    for role,path in LIVE.items():
        current=path.read_bytes()
        old=(base/(role+".before")).read_bytes()
        candidate=(base/(role+".candidate")).read_bytes()
        if current!=old and current!=candidate:
            raise RuntimeError("Meta rollback refused concurrent config drift: "+role)
    for role,path in LIVE.items():
        old=(base/(role+".before")).read_bytes()
        if path.read_bytes()!=old:write_atomically(path,old)
    cmd("nginx","-t")
    cmd("systemctl","reload","nginx")
    cmd("systemctl","kill","--signal=HUP","--kill-who=main","mnebydns-googlepilot.service")
    if not (base/"dns.before").read_bytes()==(base/"dns.candidate").read_bytes():
        # A rollback is only effective after CoreDNS reload.
        if b"    reload 5s 1s" in (base/"dns.before").read_bytes():
            time.sleep(7)
        else:
            cmd("systemctl","restart","mnebydns-dot.service")
    check_services()
    for role,path in LIVE.items():
        if path.read_bytes()!=(base/(role+".before")).read_bytes():
            raise RuntimeError("Meta rollback byte verification failed: "+role)
    (base/"pending").unlink()
    (base/"restored").write_text(datetime.now(timezone.utc).isoformat())
    print("meta_rollback_restored_three_configs=true",flush=True)

def deploy(runid:str,work:Path) -> None:
    if os.environ.get("MNEBY_META_ROUTE_APPROVED")!="EXPLICIT_OWNER_FOREIGN_META_FAMILY_CANARY":
        raise RuntimeError("Release not approved")
    if not RUN_RE.fullmatch(runid):raise ValueError("Bad Actions run ID")
    if not work.is_dir() or work.is_symlink():raise ValueError("Missing trusted staged code")
    if os.geteuid()!=0:raise PermissionError("Only root may activate")
    base=RUNROOT/runid
    with locked():
        verify_checkpoint()
        owner_quiescent()
        check_services()
        if base.exists():raise RuntimeError("Existing Meta run ID")
        RUNROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
        base.mkdir(mode=0o700)
        for role,path in LIVE.items():
            shutil.copy2(path,base/(role+".before"))
        shutil.copy2(work/"mnebydns-meta-foreign-live-20261112.py",base/"live.py")
        shutil.copy2(work/"mnebydns-meta-foreign-family-render-20261112.py",base/"renderer.py")
        old_checkpoint=CURRENT.read_text()
        (base/"checkpoint.before").write_text(old_checkpoint)
        render_mod=renderer(base/"renderer.py")
        candidate=render_mod.render(*(LIVE[role].read_text() for role in ("dns","nginx","proxy")))
        for name,content in candidate.items():
            role=name.split(".",1)[0]
            role={"Corefile":"dns","nginx":"nginx","googlepilot":"proxy"}[role]
            out=base/(role+".candidate")
            out.write_text(content)
            out.chmod(0o600)
        cmd("nginx","-t","-c",str(base/"nginx.candidate"))
        cmd("nginx","-t","-c",str(base/"proxy.candidate"))
        validate_candidate_dns(base/"dns.candidate",base)
        # Existing paths must work BEFORE any modification.
        for host in ("www.youtube.com","gemini.google.com","claude.ai"):
            local_tls(host)
        for host in ("www.instagram.com","i.instagram.com","graph.instagram.com"):
            try:
                with socket.create_connection((host,443),timeout=9) as p:
                    p.settimeout(9)
                    with ssl.create_default_context().wrap_socket(p,server_hostname=host) as t:
                        if not t.getpeercert():raise RuntimeError("No Meta origin certificate")
            except Exception as exc:
                raise RuntimeError("Meta direct origin TLS failed before deploy: "+host) from exc
        # Recovery timer is persistent and independent of Actions connection.
        write_timer(base,runid)
        (base/"pending").write_text("timed canary\n")
        try:
            # Install downstream first, DNS last to minimize broken-client window.
            write_atomically(LIVE["proxy"],(base/"proxy.candidate").read_bytes())
            cmd("systemctl","kill","--signal=HUP","--kill-who=main","mnebydns-googlepilot.service")
            write_atomically(LIVE["nginx"],(base/"nginx.candidate").read_bytes())
            cmd("nginx","-t")
            cmd("systemctl","reload","nginx")
            write_atomically(LIVE["dns"],(base/"dns.candidate").read_bytes())
            if b"    reload 5s 1s" in LIVE["dns"].read_bytes():
                time.sleep(8)
            else:cmd("systemctl","restart","mnebydns-dot.service")
            check_services()
            test_dns(port=853)
            for host in ("www.instagram.com","i.instagram.com","graph.instagram.com",
                         "www.youtube.com","gemini.google.com","claude.ai"):
                local_tls(host)
            for role,path in LIVE.items():
                if path.read_bytes()!=(base/(role+".candidate")).read_bytes():
                    raise RuntimeError("After-apply config drift: "+role)
            print("meta_foreign_17_families_canary_active=true",flush=True)
            print("meta_native_instagram_app_unverified=true",flush=True)
            print("meta_no_sni_fragmentation=true",flush=True)
        except BaseException:
            try:restore_unlocked(base)
            except Exception:
                print("meta_emergency_recovery_pending_timer=true",flush=True)
            raise

def rollback(runid:str) -> None:
    if not RUN_RE.fullmatch(runid):raise ValueError("Bad run ID")
    base=RUNROOT/runid
    with locked():
        restore_unlocked(base)

def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("deploy","rollback"))
    p.add_argument("run_id")
    p.add_argument("--work",type=Path)
    args=p.parse_args()
    if args.mode=="deploy":
        if args.work is None:raise ValueError("--work required")
        deploy(args.run_id,args.work)
    else:rollback(args.run_id)

if __name__=="__main__":
    main()
