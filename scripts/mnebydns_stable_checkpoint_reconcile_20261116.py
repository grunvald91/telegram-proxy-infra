#!/usr/bin/env python3
"""Guarded MNEBYDNS stable checkpoint reconciliation; never changes live configs.

Inspect defaults to read-only. Promotion changes ONLY stable checkpoint pointer
after exact sha256, active-service, no-pending-canary and global-lock checks.
"""
import datetime
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT=Path("/opt/mnebydns-stable-checkpoints")
POINTER=ROOT/"current"
LOCK=Path("/run/lock/mnebyvpn-public-route.lock")
LIVE={"dns":Path("/opt/mnebydns-dot/Corefile"),
      "nginx":Path("/etc/nginx/nginx.conf"),
      "proxy":Path("/etc/mnebydns-googlepilot/nginx.conf")}
EXPECTED_LIVE={
 "dns":"27623cd07fb895664089de7a621de536d6eeec8f40d005546470852cb9f7775a",
 "nginx":"d4acc6190fc0ff20258412a6ca3b059e0f68f4601b2955bbf24ebd894d8decf8",
 "proxy":"c16b663261879317e219b17cdca0ab5ab086a574e3fd6f1e45973256d95fd394"}
EXPECTED_PREVIOUS_DNS="8a9256119353ed85a3839d127a5e767e6c8aa2271e817bf52c4e0e123adb43e7"
EXPECTED_PREVIOUS_PROXY="d7f7458d71daaf8b651b909f66583433e2b38dc62df55571c5d83bd7e88bb0e6"
SENSITIVE_TIMERS=("mnebydns-owner-rollback","mnebydns-fastpath-rollback",
                  "mnebydns-safe-recover","mnebydns-ru-fastpath",
                  "threads-rollback","mnebydns-googlepilot-rollback")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(*args,timeout=10):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError("Required command unavailable: "+args[0])
    return p.stdout
def current_source():
    if POINTER.is_symlink() or not POINTER.is_file():
        raise RuntimeError("Stable pointer must be a regular file")
    old=POINTER.read_text().strip()
    if not re.fullmatch(r"/opt/mnebydns-stable-checkpoints/[0-9]+",old):
        raise RuntimeError("Unexpected stable pointer format")
    root=Path(old)
    if root.is_symlink() or not root.is_dir():raise RuntimeError("Stable source invalid")
    p=subprocess.run(["sha256sum","-c","stable-manifest.sha256"],
                     cwd=root,capture_output=True,text=True,timeout=9)
    if p.returncode:raise RuntimeError("Previous stable checkpoint integrity failed")
    return root


def inspect():
    old=current_source()
    hashes={name:sha(path) for name,path in LIVE.items()}
    oldhash={name:sha(old/(name+".stable")) for name in LIVE}
    for key,v in EXPECTED_LIVE.items():
        if hashes[key]!=v:raise RuntimeError("Production config drift; refuse checkpoint promotion: "+key)
    outdated=(oldhash["dns"]==EXPECTED_PREVIOUS_DNS and
              oldhash["proxy"]==EXPECTED_PREVIOUS_PROXY)
    current=(oldhash["dns"]==EXPECTED_LIVE["dns"] and
             oldhash["proxy"]==EXPECTED_LIVE["proxy"])
    if (not (outdated or current) or
        oldhash["nginx"]!=EXPECTED_LIVE["nginx"]):
        raise RuntimeError("Unexpected prior stable checkpoint")
    dns=LIVE["dns"].stat()
    if not (dns.st_uid==0 and dns.st_gid==grp.getgrnam("mnebydns-corefile-readers").gr_gid
            and stat.S_IMODE(dns.st_mode)==0o640):
        raise RuntimeError("CoreDNS reader group not healthy")
    states={}
    for unit in ("mnebydns-dot.service","nginx.service","mnebydns-googlepilot.service"):
        states[unit]=(run("systemctl","is-active",unit,timeout=7).strip()=="active")
    if not all(states.values()):raise RuntimeError("Production services not all active")
    listeners={}
    for key,port in (("dns",853),("nginx",443),("proxy",15449)):
        listeners[key]=bool(run("ss","-H","-lnt","sport = :"+str(port),timeout=7).strip())
    if not all(listeners.values()):raise RuntimeError("Production TCP listeners not all active")
    timers=run("systemctl","list-timers","--all","--no-legend","--no-pager")
    pending=[name for name in SENSITIVE_TIMERS if name in timers]
    # Additional per-transaction owner files may exist but cannot be fully
    # enumerated from timers alone; the stable source check is still required.
    status={"read_only":True,"current_stable":old.name,"live_matches_expected":True,
            "stable_diff":{"dns":oldhash["dns"]!=hashes["dns"],
                           "nginx":oldhash["nginx"]!=hashes["nginx"],
                           "proxy":oldhash["proxy"]!=hashes["proxy"]},
            "sensitive_timers_present":pending,
            "services":states,"listeners":listeners,
            "ready_to_promote":outdated and not pending,
            "already_reconciled":current}
    return old,status


def promote():
    if os.geteuid()!=0 or os.environ.get("MNEBYDNS_APPROVE_STABLE_RECONCILE")!="1":
        raise PermissionError("Root and explicit approved reconciliation required")
    with LOCK.open("a+") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old,status=inspect()
        if not status["ready_to_promote"]:raise RuntimeError("Active rollback canary; refuse")
        if not (status["stable_diff"]["dns"] and status["stable_diff"]["proxy"]
                and not status["stable_diff"]["nginx"]):
            raise RuntimeError("Unexpected stable transition delta")
        target=ROOT/str(int(time.time()))
        target.mkdir(mode=0o700)
        try:
            for kind,p in LIVE.items():
                dest=target/(kind+".stable")
                shutil.copy2(p,dest)
                with dest.open("rb") as fd:os.fsync(fd.fileno())
            manifest="".join(EXPECTED_LIVE[k]+"  "+k+".stable\n" for k in ("nginx","dns","proxy"))
            with (target/"stable-manifest.sha256").open("x") as fd:
                fd.write(manifest);fd.flush();os.fsync(fd.fileno())
            for k in LIVE:
                if sha(target/(k+".stable"))!=EXPECTED_LIVE[k]:
                    raise RuntimeError("Staged checkpoint drift")
            fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
            # Confirm again with the global route lock held before publication.
            now,check=inspect()
            if now!=old or not check["ready_to_promote"]:
                raise RuntimeError("Checkpoint changed during staging")
            if POINTER.is_symlink() or POINTER.read_text().strip()!=str(old):
                raise RuntimeError("Stable pointer concurrently changed")
            fd,path=tempfile.mkstemp(prefix=".current.next-",dir=ROOT)
            try:
                p=POINTER.stat()
                os.fchown(fd,p.st_uid,p.st_gid)
                os.fchmod(fd,stat.S_IMODE(p.st_mode))
                os.write(fd,(str(target)+"\n").encode())
                os.fsync(fd)
            finally:os.close(fd)
            os.replace(path,POINTER)
            dirfd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(dirfd)
            finally:os.close(dirfd)
            if POINTER.read_text().strip()!=str(target):
                raise RuntimeError("Stable pointer verification failed")
            print(json.dumps({"promoted":True,"old_checkpoint":old.name,"new_checkpoint":target.name,
                              "live_dns_configs_changed":False,
                              "customer_credentials_changed":False},sort_keys=True))
        except Exception:
            # Never remove a potentially published checkpoint.
            if POINTER.read_text().strip()==str(old):
                shutil.rmtree(target,ignore_errors=True)
            raise


if __name__=="__main__":
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ("inspect","promote"):
            raise ValueError("Usage: inspect | promote")
        if sys.argv[1]=="inspect":
            _,obj=inspect()
            print(json.dumps(obj,sort_keys=True))
        else:promote()
    except Exception as exc:
        print(json.dumps({"done":False,"error":type(exc).__name__,
                          "reason":str(exc)[:130]},sort_keys=True))
        raise SystemExit(1)
