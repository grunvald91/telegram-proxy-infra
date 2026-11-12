#!/usr/bin/env python3
"""One guarded mass switch for reviewed exact DNS hosts, not a general proxy.

Stages one reversible CoreDNS + Nginx candidate, validates every exact host
and unaffected services, commits checkpoint first, then commits ALL matching
Postgres PENDING rows atomically. Never claims success from HTTP preflight.
A 60 minute independent systemd timer restores the prior live files if this
runner dies before checkpoint confirmation. A separate strict compensation
restores the old checkpoint if the subsequent DB commit conclusively fails.
"""
from __future__ import annotations
import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex

ROOT=Path(__file__).resolve().parent.parent
PREPARE=ROOT/"scripts/mnebydns-108-bulk-prepare-20261112.py"
spec=importlib.util.spec_from_file_location("bulk_prepare",PREPARE)
assert spec and spec.loader
prepare=importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
batch=prepare.batch
owner=batch.owner
OUTPUT=prepare.OUTPUT
RUNID=os.environ.get("GITHUB_RUN_ID","")
WORK="/tmp/mnebydns-mass-"+RUNID
BASE="/opt/mnebydns-owner-domain/"+RUNID

def event(code,**kwargs):
    OUTPUT.mkdir(exist_ok=True)
    data=dict(code=code,**kwargs)
    with (OUTPUT/"deploy-events.jsonl").open("a") as f:
        f.write(json.dumps(data,ensure_ascii=False,sort_keys=True)+"\n")
    print("MASS_BULK_EVENT="+json.dumps(data,ensure_ascii=False,sort_keys=True),flush=True)

def checked_plan():
    if not re.fullmatch(r"[1-9][0-9]{8,12}",RUNID):
        raise RuntimeError("Invalid unique GitHub run ID")
    plan=json.loads((OUTPUT/"plan.json").read_text())
    names=batch.inventory()
    selected=plan.get("selected")
    if not isinstance(selected,list) or not selected or len(selected)>108:
        raise RuntimeError("Empty or oversized bulk candidate set")
    seen=set()
    for row in selected:
        name=owner._render.validate_domain(row["domain"])
        ip=owner._render.validated_public_ip(row["ip"])
        if name in seen or name not in names or ip!=row["ip"]:
            raise RuntimeError("Non-attested or duplicate staged hostname")
        seen.add(name)
    if plan.get("deploy_count")!=len(selected):
        raise RuntimeError("Plan count mismatch")
    for file,key in (("dns.before","dns_before_sha256"),("nginx.before","nginx_before_sha256"),
                     ("dns.pilot","dns_pilot_sha256"),("nginx.pilot","nginx_pilot_sha256")):
        blob=(OUTPUT/file).read_bytes()
        if hashlib.sha256(blob).hexdigest()!=plan[key]:
            raise RuntimeError("Candidate checksum mismatch: "+file)
    if not os.getenv("RU_PASS") or not os.getenv("DE_PASS"):
        raise RuntimeError("Production SSH secrets missing")
    return plan

REMOTE_EDGE=r"""
import base64,concurrent.futures,json,re,socket,ssl,sys
hosts=json.loads(base64.b64decode(sys.argv[1],validate=True))
ip=sys.argv[2]
ctx=ssl.create_default_context()
ctx.set_alpn_protocols(["http/1.1"])
def one(host):
    try:
        with socket.create_connection((ip,443),timeout=9) as s:
            s.settimeout(9)
            with ctx.wrap_socket(s,server_hostname=host) as t:
                if not t.getpeercert():raise RuntimeError("CERT_MISSING")
                t.sendall(("GET / HTTP/1.1\r\nHost: "+host+
                    "\r\nUser-Agent: MNEBYDNS-ReadOnly-Research/1.0\r\n"
                    "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii"))
                head=t.recv(512)
                m=re.match(rb"HTTP/1\.[01] ([1-5][0-9]{2})\b",head)
                if m: return [host,int(m.group(1)),"OK"]
                return [host,None,"INVALID_HTTP"]
    except (OSError,ssl.SSLError,RuntimeError) as e:
        return [host,None,type(e).__name__]
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    for x in pool.map(one,hosts):
        print(json.dumps(x),flush=True)
"""

def verify_public_https(selected):
    hosts=[row["domain"] for row in selected]
    token=base64.b64encode(json.dumps(hosts).encode()).decode()
    cmd="python3 -c "+shlex.quote(REMOTE_EDGE)+" "+shlex.quote(token)+" "+shlex.quote(owner.EDGE)
    raw=owner.ssh("ru",cmd,420)
    res=[json.loads(line) for line in raw.splitlines()]
    if len(res)!=len(hosts) or [r[0] for r in res]!=hosts:
        raise RuntimeError("Incomplete or reordered RU to DE canary results")
    failed=[dict(domain=h,code=code,error=why) for h,code,why in res
            if type(code) is not int or not 200<=code<400 or why!="OK"]
    event("BULK_PUBLIC_HTTPS",verified=len(hosts)-len(failed),failed=failed)
    if failed:
        raise RuntimeError("RU_TO_DE_HTTPS_CANDIDATE_FAILURE")

def verify_dot(selected):
    # Only the first host incurs the established repeated stable DoT and
    # excluded-domain checks. Every remaining host still checks A, AAAA,
    # CNAME, HTTPS, SVCB for accidental non-edge answers.
    owner.oracle_canary_check(selected[0]["domain"],True)
    def one(item):
        host=item["domain"]
        try:
            for code in (1,5,28,64,65):
                status,ips=owner.dns_q(host,code)
                if status!=0:raise RuntimeError("DOT_BAD_RCODE")
                if code==1 and ips!=[owner.EDGE]:raise RuntimeError("DOT_A_NOT_EDGE")
                if code!=1 and ips:raise RuntimeError("DOT_ALT_RR")
            return (host,"OK")
        except Exception as exc:
            return (host,type(exc).__name__+":"+str(exc)[:80])
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results=list(pool.map(one,selected))
    failed=[dict(domain=h,reason=state) for h,state in results if state!="OK"]
    event("BULK_DOT",verified=len(results)-len(failed),failed=failed)
    if failed:raise RuntimeError("BULK_DOT_CANDIDATE_FAILURE")
    batch.capacity()

def bulk_sql(selected):
    # Inputs are ONLY fixed inventory hostnames and validated global IPv4
    # addresses. An SQL exception causes a transaction rollback (no partial
    # ACTIVE rows). Revision increments match the existing owner controller.
    values=",".join("('"+x["domain"]+"','"+x["ip"]+"')" for x in selected)
    n=len(selected)
    return ("BEGIN;\n"
      "DO $mass$ DECLARE changed integer; BEGIN\n"
      "UPDATE dns_admin_domains d SET status='ACTIVE',revision=revision+1,"
      "updated_at=now(),applied_at=now(),confirmed_at=now(),"
      "verified_origin_ip=v.ip::inet,last_error_code=NULL,"
      "canary_run_id=NULL,canary_expires_at=NULL\n"
      "FROM (VALUES "+values+") AS v(domain,ip)\n"
      "WHERE d.domain=v.domain AND d.product='Research 2026-11'"
      " AND d.status='PENDING';\n"
      "GET DIAGNOSTICS changed=ROW_COUNT;\n"
      "IF changed<>"+str(n)+" THEN RAISE EXCEPTION 'MASS_BULK_DB_CAS_FAILED'; END IF;\n"
      "END $mass$;\nCOMMIT;")

def database_states(selected):
    names=",".join("'"+item["domain"]+"'" for item in selected)
    raw=owner.sql("SELECT domain||'|'||status||'|'||coalesce(product,'')||'|'||"
                  "coalesce(verified_origin_ip::text,'') FROM dns_admin_domains "
                  "WHERE domain IN ("+names+") ORDER BY domain")
    out={}
    for l in raw.splitlines():
        split=l.split("|")
        if len(split)!=4 or split[0] in out:
            raise RuntimeError("Ambiguous DB readback")
        host,status,product,ip=split
        out[host]=(status,product,ip)
    if set(out)!={r["domain"] for r in selected}:
        raise RuntimeError("Missing DB readback rows")
    return out

def states_are(selected,state):
    rows=database_states(selected)
    for x in selected:
        status,product,ip=rows[x["domain"]]
        if status!=state or product!=batch.PRODUCT:
            return False
        if state=="ACTIVE" and owner.pg_inet_host(ip)!=x["ip"]:
            return False
    return True

def transfer(selected):
    # Pinned two-server SSH trust inherited from the established owner
    # route reconciler. No free-form shell interpolation from public input.
    owner.ssh("de","test ! -e "+shlex.quote(WORK)+
              " && install -d -m 700 "+shlex.quote(WORK),45)
    files=[
        ("dns.before","dns.before"),("nginx.before","nginx.before"),
        ("dns.pilot","dns.pilot"),("nginx.pilot","nginx.pilot"),
        ("plan.json","plan.json"),
        ("scripts/mnebydns-owner-domain-rollback-20261110.sh","rollback.sh"),
        ("scripts/mnebydns-owner-domain-confirm-20261110.sh","confirm.sh"),
        ("scripts/mnebydns-dot-config-change-20261111.sh","reload.sh"),
        ("scripts/mnebydns-108-bulk-stage-20261112.sh","stage.sh"),
        ("scripts/mnebydns-108-bulk-compensate-20261112.sh","compensate.sh"),
    ]
    checks=[]
    p=json.loads((OUTPUT/"plan.json").read_text())
    for name,key in (("dns.before","dns_before_sha256"),("nginx.before","nginx_before_sha256"),
                     ("dns.pilot","dns_pilot_sha256"),("nginx.pilot","nginx_pilot_sha256")):
        checks.append(p[key]+"  "+name)
    (OUTPUT/"checksums.sha256").write_text("\n".join(checks)+"\n")
    files.append(("checksums.sha256","checksums.sha256"))
    password=os.environ["DE_PASS"]
    for src,dst in files:
        path=(ROOT/src) if src.startswith("scripts/") else (OUTPUT/src)
        if not path.is_file() or path.is_symlink():raise RuntimeError("Unsafe source file")
        owner.cmd(["sshpass","-e","scp","-q","-o","ConnectTimeout=12",
            *owner.SSH_TRUST,"-o","LogLevel=ERROR",
            str(path),"root@"+owner.EDGE+":"+WORK+"/"+dst],password,timeout=90)
    event("BULK_FILES_STAGED",count=len(files))

def deploy():
    plan=checked_plan()
    selected=plan["selected"]
    # The current scan+plan must be performed in this same workflow run.
    if not prepare.SCAN.is_file() or not owner.live_checkpoint_unchanged():
        raise RuntimeError("Missing fresh plan or clean production checkpoint")
    batch.ensure_quiet()
    batch.capacity()
    if not states_are(selected,"PENDING"):
        raise RuntimeError("Research ownership changed since preparation")
    event("BEGIN",candidate_count=len(selected),excluded=len(plan["excluded"]))
    staged=False
    confirmed=False
    db_committed=False
    try:
        transfer(selected)
        deadline=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S UTC")
        cmd="bash "+shlex.quote(WORK+"/stage.sh")+" "+ " ".join(
            shlex.quote(x) for x in (WORK,RUNID,deadline))
        resp=owner.ssh("de",cmd,170)
        if "MASS_BULK_STAGE_ACTIVE=true" not in resp:
            raise RuntimeError("Mass stage not acknowledged")
        staged=True
        event("STAGE_OK",rollback_expiry_utc=deadline)
        verify_dot(selected)
        verify_public_https(selected)
        # One more stable DNS regression before accepting a promoted checkpoint.
        owner.oracle_canary_check(selected[-1]["domain"],True)
        if not states_are(selected,"PENDING"):
            raise RuntimeError("DB_CHANGED_BEFORE_CHECKPOINT_CONFIRM")
        resp=owner.ssh("de","bash "+shlex.quote(BASE+"/confirm.sh")+" "+shlex.quote(BASE),90)
        if ("owner_domain_confirmed_stable=true" not in resp and
            "owner_domain_already_confirmed=true" not in resp):
            raise RuntimeError("CHECKPOINT_CONFIRM_NOT_VERIFIED")
        confirmed=True
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("CONFIRMED_CHECKPOINT_NOT_STABLE")
        event("CHECKPOINT_CONFIRMED",count=len(selected))
        owner.sql(bulk_sql(selected))
        if not states_are(selected,"ACTIVE"):
            raise RuntimeError("Post-commit ACTIVE readback mismatch")
        db_committed=True
        event("COMPLETE",active=len(selected),route_checks="PASS")
    except Exception as exc:
        event("FAILED",error_type=type(exc).__name__,reason=str(exc)[:250])
        if not db_committed:
            if not confirmed:
                try: confirmed=owner.is_confirmed(RUNID)
                except Exception: pass
            if confirmed:
                # A lost DB reply may still mean COMMIT succeeded. Never
                # compensate until all rows are conclusively still PENDING.
                if states_are(selected,"ACTIVE"):
                    event("DB_COMMIT_RECOVERED",count=len(selected))
                    return
                if not states_are(selected,"PENDING"):
                    raise RuntimeError("MASS_INCIDENT_DB_STATE_UNKNOWN") from exc
                resp=owner.ssh("de","bash "+shlex.quote(BASE+"/compensate.sh")+" "+shlex.quote(BASE),130)
                if "MASS_BULK_COMPENSATING_RESTORE_VERIFIED=true" not in resp or not owner.live_checkpoint_unchanged():
                    raise RuntimeError("MASS_INCIDENT_COMPENSATION_NOT_VERIFIED") from exc
                event("COMPENSATED",result="PRIOR_STABLE_CHECKPOINT_RESTORED")
            elif staged or not owner.live_checkpoint_unchanged():
                owner.rollback_or_unchanged(RUNID)
                if not owner.live_checkpoint_unchanged():
                    raise RuntimeError("MASS_INCIDENT_INDEPENDENT_ROLLBACK_NOT_VERIFIED") from exc
                event("ROLLED_BACK",result="PRIOR_STABLE_CHECKPOINT_RESTORED")
        raise

def self_test():
    os.environ.setdefault("GITHUB_RUN_ID","12345678901")
    x=[dict(domain="valid.example.com",ip="93.184.215.14")]
    # SQL is non-executable until explicitly called in the gated deploy mode.
    q=bulk_sql(x)
    assert "BEGIN;" in q and "COMMIT;" in q and "GET DIAGNOSTICS changed=ROW_COUNT" in q
    assert "d.status='PENDING'" in q and "d.product='Research 2026-11'" in q
    assert "verified_origin_ip=v.ip::inet" in q
    assert "MASS_BULK_DB_CAS_FAILED" in q
    print("MASS_BULK_OFFLINE_SELF_TEST=PASS",flush=True)

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("mode",choices=("self-test","deploy"))
    args=a.parse_args()
    if args.mode=="self-test":self_test()
    else:deploy()
