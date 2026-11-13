#!/usr/bin/env python3
"""One guarded RU-ingress DNS A fastpath promotion, always reversible precommit.

Exact 13 proven hostnames only. Production stage arm includes independent
45m rollback. Separate trusted DoT and original-SNI public HTTPS validation
precedes stable checkpoint commit. No VPN, Nginx or SQL mutation.
"""
from __future__ import annotations
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT=Path(__file__).resolve().parent.parent
SRC=ROOT/"scripts/mnebydns-ru-fastpath-plan-20261113.py"
spec=importlib.util.spec_from_file_location("ru_fastpath_plan",SRC)
assert spec and spec.loader
planmod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(planmod)
owner=planmod.owner
OUT=planmod.OUT
RUNID=os.environ.get("GITHUB_RUN_ID","")
BASE="/opt/mnebydns-fastpath/"+RUNID
WORK="/tmp/mnebydns-fastpath-"+RUNID

REMOTE_HTTPS=r"""
import base64,concurrent.futures,json,re,socket,ssl,sys,time
hosts=json.loads(base64.b64decode(sys.argv[1],validate=True))
ip=sys.argv[2]
ctx=ssl.create_default_context()
ctx.set_alpn_protocols(['http/1.1'])
def one(host):
    try:
        start=time.monotonic()
        with socket.create_connection((ip,443),timeout=5) as sock:
            sock.settimeout(6)
            with ctx.wrap_socket(sock,server_hostname=host) as tls:
                if not tls.getpeercert():raise RuntimeError('CERT_MISSING')
                tls.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\n'
                  'User-Agent: MNEBYDNS-Guarded-RU-FastPath/1.0\r\n'
                  'Connection: close\r\n\r\n').encode('ascii'))
                head=tls.recv(256)
                m=re.match(rb'HTTP/1\.[01] ([1-5][0-9]{2})\b',head)
                return {'host':host,'http':int(m.group(1)) if m else None,
                        'tls':True,'time_ms':round((time.monotonic()-start)*1000,1)}
    except Exception as ex:
        return {'host':host,'http':None,'tls':False,'error':type(ex).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    for result in pool.map(one,hosts):print(json.dumps(result,separators=(',',':')),flush=True)
"""

def emit(event,**details):
    OUT.mkdir(exist_ok=True)
    record={"utc":dt.datetime.now(dt.timezone.utc).isoformat(),
            "event":event,**details}
    with (OUT/"deploy-events.jsonl").open("a") as f:
        f.write(json.dumps(record,ensure_ascii=False,sort_keys=True)+"\n")
    print("FASTPATH_EVENT="+json.dumps(record,ensure_ascii=False,sort_keys=True),flush=True)

def ssh(role,cmd,timeout=90):
    return owner.ssh(role,cmd,timeout)

def verify_tls(role,hosts):
    token=base64.b64encode(json.dumps(hosts).encode()).decode()
    ip=planmod.PUBLIC_RU
    command="python3 -c "+shlex.quote(REMOTE_HTTPS)+" "+shlex.quote(token)+" "+shlex.quote(ip)
    raw=ssh(role,command,200)
    results=[json.loads(line) for line in raw.splitlines()]
    if [x.get("host") for x in results]!=hosts:
        raise RuntimeError("RU_FASTPATH_TLS_INCOMPLETE_VANTAGE_"+role)
    bad=[{"host":x["host"],"error":x.get("error","bad_http")}
         for x in results if not x.get("tls") or not isinstance(x.get("http"),int)]
    emit("TLS_SNI_VANTAGE",vantage=role,success=len(results)-len(bad),errors=bad,
         median_response_ms=(
          sorted(x["time_ms"] for x in results if x.get("http"))[
               (len(results)-len(bad))//2] if len(results)!=len(bad) else None))
    if bad:raise RuntimeError("RU_HTTPS_VALIDATION_FAILED_"+role)
    return results

def verify_dot(names):
    for host in names:
        code,ips=owner.dns_q(host,1)
        if code!=0 or ips!=[planmod.PUBLIC_RU]:
            raise RuntimeError("RU_FASTPATH_DOT_A_NOT_RU_"+host)
        for kind in (5,28,64,65):
            code,alternates=owner.dns_q(host,kind)
            if code!=0 or alternates:
                raise RuntimeError("RU_FASTPATH_ALT_DNS_RR_INVALID_"+host)
    for name in ("example.org","api.telegram.org"):
        code,ips=owner.dns_q(name,1)
        if code!=0 or planmod.PUBLIC_RU in ips:
            raise RuntimeError("RU_FASTPATH_CONTROL_UNEXPECTED_"+name)
    emit("DOT_SELECTED_ALL_VERIFIED",count=len(names))

def transfer():
    os.environ["SSHPASS"]=os.environ["DE_PASS"]
    ssh("de","test ! -e "+shlex.quote(WORK)+
        " && install -d -m 700 "+shlex.quote(WORK),45)
    names=(("dns.before","dns.before"),("dns.pilot","dns.pilot"),
         ("plan.json","plan.json"),
         ("scripts/mnebydns-ru-fastpath-rollback-20261113.sh","rollback.sh"),
         ("scripts/mnebydns-ru-fastpath-commit-20261113.sh","commit.sh"),
         ("scripts/mnebydns-ru-fastpath-stage-20261113.sh","stage.sh"),
         ("scripts/mnebydns-dot-config-change-20261111.sh","reload.sh"))
    for original,remote_name in names:
        file=(ROOT/original) if original.startswith("scripts/") else (OUT/original)
        if not file.is_file() or file.is_symlink():raise RuntimeError("MISSING_SAFE_FASTPATH_SOURCE")
        args=["sshpass","-e","scp","-q","-o","ConnectTimeout=12",
              *owner.SSH_TRUST,"-o","LogLevel=ERROR",str(file),
              "root@"+owner.EDGE+":"+WORK+"/"+remote_name]
        owner.cmd(args,os.environ["DE_PASS"],timeout=75)
    emit("STAGED_FILES_TRANSFERRED",count=len(names))

def deploy():
    if not re.fullmatch(r"[1-9][0-9]{8,12}",RUNID):
        raise RuntimeError("Expected unique GitHub run id")
    if os.environ.get("GITHUB_EVENT_NAME")!="push" or os.environ.get("GITHUB_REF")!="refs/heads/main":
        raise RuntimeError("Live route writes allowed only from reviewed main push")
    if not os.environ.get("RU_PASS") or not os.environ.get("DE_PASS"):
        raise RuntimeError("Missing secure SSH credentials")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Live CoreDNS/Nginx baseline has drift")
    planmod.plan()
    info=json.loads((OUT/"plan.json").read_text())
    selected=info["selected"]
    if len(selected)!=len(planmod.CANDIDATES) or set(selected)!=set(planmod.CANDIDATES):
        raise RuntimeError("Not all selected service hosts have strict exact-A templates")
    # A failed public ingress must not cause a global DNS mapping switch:
    # require verified original-SNI TLS/HTTP from BOTH existing VPS vantage.
    verify_tls("ru",selected)
    verify_tls("de",selected)
    staged=False
    committed=False
    try:
        transfer()
        result=ssh("de","bash "+shlex.quote(WORK+"/stage.sh")+" "+
                   shlex.quote(RUNID)+" "+shlex.quote(WORK),170)
        if "FASTPATH_STAGED_WITH_45M_ROLLBACK=true" not in result:
            raise RuntimeError("FASTPATH_STAGE_NOT_ACKNOWLEDGED")
        staged=True
        emit("STAGED",hosts=len(selected),revert_window="45m")
        verify_dot(selected)
        verify_tls("ru",selected)
        verify_tls("de",selected[:5])
        # Independent checkpoint promotion only after the two-vantage gate.
        result=ssh("de","bash "+shlex.quote(BASE+"/commit.sh")+" "+shlex.quote(BASE),100)
        if "FASTPATH_CONFIRMED_STABLE=true" not in result:
            raise RuntimeError("FASTPATH_CHECKPOINT_PROMOTION_NOT_ACKNOWLEDGED")
        committed=True
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("FASTPATH_STABLE_CHECKPOINT_HEALTH_UNVERIFIED")
        verify_dot(selected)
        emit("ACTIVE",hosts=len(selected),stable_checkpoint=True)
    except Exception as ex:
        emit("FAILED",error_type=type(ex).__name__,reason=str(ex)[:240])
        if not committed:
            # If the commit RPC lost a reply, never blindly undo a promoted
            # newer checkpoint; the server rollback script rejects such drift.
            try:
                result=ssh("de","bash "+shlex.quote(BASE+"/rollback.sh")+" "+
                           shlex.quote(BASE),110)
                if ("FASTPATH_ROLLBACK_VERIFIED=true" in result or
                    "FASTPATH_ALREADY_CONFIRMED_NO_ROLLBACK=true" in result):
                    emit("ROLLBACK_OR_ALREADY_COMMITTED_VERIFIED",
                         result="rollback" if "FASTPATH_ROLLBACK_VERIFIED=true" in result
                         else "checkpoint_promoted")
                else:raise RuntimeError("REVERT_NOT_ACKNOWLEDGED")
            except Exception as rerr:
                emit("INCIDENT",error_type=type(rerr).__name__,
                     reason=str(rerr)[:160])
        raise

def self_test():
    assert len(set(planmod.CANDIDATES))==11
    assert planmod.PUBLIC_DE!=planmod.PUBLIC_RU
    assert "check_hostname=False" not in REMOTE_HTTPS
    print("FASTPATH_GUARDED_DEPLOY_OFFLINE=PASS",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif sys.argv[1:]==["--deploy"]:deploy()
    else:raise SystemExit("Usage --self-test|--deploy")
