#!/usr/bin/env python3
"""One-time guarded repair: CoreDNS DynamicUser must be able to read Corefile.

Changes group ownership only, starts pre-existing systemd DoT service.
Does not change DNS rules, sites, customer records, keys or firewall.
"""
import datetime
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

SERVICE="mnebydns-dot.service"
CORE=Path("/opt/mnebydns-dot/Corefile")
EXPECTED_SHA="27623cd07fb895664089de7a621de536d6eeec8f40d005546470852cb9f7775a"
READER_GROUP="mnebydns-corefile-readers"
OUT={"operation":"repair_dot_corefile_group_only","utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
     "changed_dns_bytes":False,"changed_certificates":False,"changed_customer_access":False}
def command(*args,timeout=25):
    p=subprocess.run(list(args),capture_output=True,text=True,timeout=timeout)
    if p.returncode!=0:raise RuntimeError("Command failed: "+args[0]+" "+args[1]+" rc="+str(p.returncode))
    return p.stdout.strip()
def alive():
    return subprocess.run(["systemctl","is-active","--quiet",SERVICE],capture_output=True,timeout=6).returncode==0
def listening():
    p=subprocess.run(["ss","-H","-lnt","sport = :853"],capture_output=True,text=True,timeout=6)
    return p.returncode==0 and bool(p.stdout.strip())
def main():
    assert os.geteuid()==0,"root required"
    lock=Path("/run/lock/mnebyvpn-public-route.lock")
    with open(lock,"a+") as lf:
        fcntl.flock(lf,fcntl.LOCK_EX|fcntl.LOCK_NB)
        s=CORE.lstat()
        if not stat.S_ISREG(s.st_mode) or CORE.is_symlink():
            raise RuntimeError("Corefile must be an ordinary file")
        digest=hashlib.sha256(CORE.read_bytes()).hexdigest()
        assert digest==EXPECTED_SHA,"Corefile drift, refuse permission mutation"
        assert stat.S_IMODE(s.st_mode)==0o640,"Unexpected Corefile mode"
        assert s.st_uid==0,"Unexpected Corefile owner"
        target_group=grp.getgrnam(READER_GROUP).gr_gid
        p=command("systemctl","show",SERVICE,"-p","User,DynamicUser,SupplementaryGroups")
        props=dict(line.split("=",1) for line in p.splitlines() if "=" in line)
        assert props.get("User")=="mnebydns-dot" and props.get("DynamicUser")=="yes"
        assert READER_GROUP in props.get("SupplementaryGroups","").split(),"Reader group missing from unit"
        old_gid=s.st_gid
        if old_gid not in (0,target_group):raise RuntimeError("Unexpected owner group")
        if old_gid==0:
            os.chown(CORE,-1,target_group)
            with CORE.open("rb") as f:os.fsync(f.fileno())
            OUT["group_updated"]=True
        else:
            OUT["group_updated"]=False
        s2=CORE.stat()
        if (s2.st_gid!=target_group or stat.S_IMODE(s2.st_mode)!=0o640 or
            hashlib.sha256(CORE.read_bytes()).hexdigest()!=EXPECTED_SHA):
            raise RuntimeError("Corefile group or bytes drift after repair")
        if not alive():
            command("systemctl","reset-failed",SERVICE)
            command("systemctl","start",SERVICE,timeout=35)
        if not alive() or not listening():
            raise RuntimeError("DoT unit or TCP853 not active after metadata repair")
        OUT.update(done=True,dns_active=True,tcp853_listening=True,
                   config_sha256=digest,group_is_reader=True,
                   file_mode="0640",certificates_unchanged=True)
        print(json.dumps(OUT,sort_keys=True))
if __name__=="__main__":
    try:main()
    except Exception as e:
        OUT.update(done=False,error=type(e).__name__,reason=str(e)[:160])
        print(json.dumps(OUT,sort_keys=True))
        raise SystemExit(1)
