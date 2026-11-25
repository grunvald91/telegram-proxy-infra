#!/usr/bin/env python3
"""Promote guarded SNI only; keep running DNS, catalog, controller untouched."""
import os
import pwd
import grp
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from fi_dns_ssh_stage import FI,FI_RUNTIME,host,private_dir,read,immutable,command,require
from fi_routed_stage import validated_bundle,active,ctl,listeners,check_public,proxy_tls,denied_proxy,no_override,phase
from fi_shared_routes import covered
from fi_sni_egress_guard import USER,uid,rules,verify,FINGERPRINT,table,digest

OLD="mnebyvpn-fi-sni-routed-v2.service"
NEW="mnebyvpn-fi-sni-routed-v3.service"
GUARD="mnebyvpn-fi-sni-egress-guard.service"
DNS="mnebyvpn-fi-dns-routed.service"
UNIT_DIR=Path("/etc/systemd/system")

def enabled(unit):
    return ctl("is-enabled",unit).strip()==b"enabled"

def account():
    try:p=pwd.getpwnam(USER)
    except KeyError:
        command("useradd","--system","--no-create-home","--home-dir","/nonexistent","--shell","/usr/sbin/nologin","--user-group",USER)
        p=pwd.getpwnam(USER)
    n=uid()
    require(p.pw_dir=="/nonexistent" and grp.getgrgid(p.pw_gid).gr_name==USER,"unexpected_proxy_account")
    require(sum(x.pw_uid==n for x in pwd.getpwall())==1,"shared_proxy_uid")
    require(not any(USER in g.gr_mem for g in grp.getgrall()),"unexpected_proxy_group_membership")
    return n

def counters():
    obj=table()
    require(obj is not None,"missing_guard_table")
    return sum(e["counter"]["packets"] for row in obj["nftables"] if "rule" in row and row["rule"]["chain"]=="proxy_out" and any("reject" in x for x in row["rule"]["expr"]) for e in row["rule"]["expr"] if "counter" in e)

def negative_test():
    # A real local listener is accessible to root and must be denied only
    # to the dedicated proxy account. Test no other host or firewall chain.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));listener.listen(1)
        port=listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1",port),timeout=2),listener.accept()[0]:pass
        before=counters()
        code="import socket,sys\ntry:\n s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=2);s.close();sys.exit(9)\nexcept OSError:sys.exit(0)"
        p=subprocess.run(["runuser","-u",USER,"--","/usr/bin/python3","-c",code,str(port)],capture_output=True,timeout=5)
        require(p.returncode==0 and counters()>before,"local_egress_not_denied")
    print("FI_SNI_KERNEL_LOCAL_DENIAL_VERIFIED=true",flush=True)

def probe(policy):
    for _ in range(30):
        if active(NEW) and active(GUARD) and listeners(14443)==["127.0.0.1:14443"]:break
        time.sleep(1)
    else:raise RuntimeError("guarded_proxy_not_ready")
    n=uid();expected=read(FINGERPRINT,100).decode().strip().split(":")
    require(expected[0]==str(n),"guard_uid_mismatch")
    verify(n,expected[1])
    pid=int(ctl("show",NEW,"-p","MainPID","--value").strip())
    status=dict(l.split(":",1) for l in (Path("/proc")/str(pid)/"status").read_text().splitlines() if ":" in l)
    require(all(int(x)==n for x in status["Uid"].split()) and int(status["CapEff"].strip(),16)==0,"unexpected_proxy_privileges")
    negative_test()
    names=[x for x in ("www.youtube.com","gemini.google.com","api.openai.com","claude.ai","integrate.api.nvidia.com") if covered(policy,x)]
    require(len(names)>=3,"missing_samples")
    for idx,name in enumerate(names):phase("guarded_tls_"+str(idx),lambda:proxy_tls(name),attempts=2)
    phase("guarded_unknown_sni",denied_proxy)
    verify(n,expected[1]);check_public()
    require(active(DNS) and not active(OLD),"unexpected_service_state")
    print("FI_SNI_GUARDED_TLS_VERIFIED="+str(len(names))+";UNKNOWN_SNI_DENIED=true",flush=True)

def rollback(src):
    host(FI)
    if not (src/"guard-switch").exists():return
    require(read(src/"guard-switch",100)==b"fi-sni-guard-v1\n","bad_rollback_marker")
    ctl("disable","--now",NEW)
    ctl("stop",GUARD)
    ctl("enable","--now",OLD)
    for _ in range(20):
        if active(OLD) and listeners(14443)==["127.0.0.1:14443"]:break
        time.sleep(1)
    else:raise RuntimeError("old_proxy_restore_failed")
    phase("rollback_tls",lambda:proxy_tls("www.youtube.com"),attempts=2)
    require(active(DNS),"dns_service_changed");check_public()
    (src/"guard-switch").unlink()
    print("FI_SNI_GUARD_ROLLBACK_VERIFIED=true",flush=True)

def stage(src):
    host(FI);private_dir(FI_RUNTIME);check_public()
    require(active(DNS) and active(OLD) and enabled(OLD) and not active(NEW) and not active(GUARD),"unexpected_services")
    policy,_,nginx=validated_bundle()
    require(read(FINGERPRINT.parent/"RoutedNginxV2.conf",500000)==nginx,"active_nginx_config_drift")
    n=account()
    # Syntax/kernel capability preflight with no firewall mutation.
    if table() is None:
        command("nft","-c","-f","-",input=rules(n).encode())
    require(read(FI_RUNTIME/"fi_routed_runtime.py",200000),"routed_runtime_missing")
    immutable(FI_RUNTIME/"fi_sni_egress_guard.py",read(src/"fi_sni_egress_guard.py",200000))
    for unit in (NEW,GUARD):
        no_override(unit)
        immutable(UNIT_DIR/unit,read(src/unit,10000))
    command("systemd-analyze","verify",str(UNIT_DIR/NEW),str(UNIT_DIR/GUARD),timeout=20)
    ctl("daemon-reload")
    immutable(src/"guard-switch",b"fi-sni-guard-v1\n")
    try:
        ctl("start",GUARD)
        ctl("stop",OLD)
        ctl("start",NEW)
        probe(policy)
        ctl("enable",NEW)
        ctl("disable",OLD)
        require(enabled(NEW) and active(NEW) and active(GUARD),"guarded_enable_failed")
    except BaseException:
        for unit in (GUARD,NEW):
            out=subprocess.run(["systemctl","show",unit,"-p","ActiveState","-p","SubState","-p","Result","-p","ExecMainStatus"],capture_output=True,text=True,timeout=5)
            print("FI_SNI_UNIT_STATUS="+unit+":"+",".join(x for x in out.stdout.splitlines() if re.fullmatch(r"(ActiveState|SubState|Result|ExecMainStatus)=[a-zA-Z0-9_-]+",x)),flush=True)
        rollback(src);raise
    print("FI_SNI_EGRESS_GUARD_LIVE=true;PUBLIC_DNS=false;PUBLIC_PROXY_UNCHANGED=true",flush=True)

if __name__=="__main__":
    try:
        os.umask(0o077)
        def interrupted(signum,frame):raise SystemExit(128+signum)
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGHUP,interrupted)
        require(len(sys.argv)==3 and re.fullmatch(r"/run/fi-sni-guard-[0-9]+-[0-9]+",sys.argv[2]),"invalid_stage")
        src=Path(sys.argv[2]);private_dir(src)
        if sys.argv[1]=="stage":stage(src)
        elif sys.argv[1]=="rollback":rollback(src)
        else:raise RuntimeError("invalid_action")
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.SubprocessError) as e:
        label=str(e) if re.fullmatch(r"[a-z0-9_]+",str(e)) else type(e).__name__
        print("FI_SNI_EGRESS_STAGE_BLOCKED="+label,file=sys.stderr,flush=True)
        raise SystemExit(2)
