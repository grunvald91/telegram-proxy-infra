#!/usr/bin/env python3
"""One guarded mass MNEBYDNS release (no silent partial completion).

All candidates are checked afresh, rendered in-memory, and staged only after
an independent server-side timer is active. One CoreDNS reload and one Nginx
reload. PostgreSQL PENDING->ACTIVE is a strict all-or-none SQL transaction.
"""
from __future__ import annotations
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
import traceback

import importlib.util
ROOT=Path(__file__).resolve().parent.parent
REPORT=ROOT/"bulk-108-activation-results"
def load(name,file):
    spec=importlib.util.spec_from_file_location(name, ROOT/"scripts"/file)
    if not spec or not spec.loader:
        raise RuntimeError("Missing checked-in module")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
plan=load("bulk_plan_for_live", "mnebydns-bulk-preflight-20261112.py")
batch=plan.batch
owner=plan.owner
renderer=plan.renderer

RU_HTTPS=r'''import base64,concurrent.futures,json,re,socket,ssl,sys
hosts=json.loads(base64.b64decode(sys.argv[1]))
edge=sys.argv[2]
def probe(host):
 stage="TCP"
 try:
  with socket.create_connection((edge,443),timeout=9) as tcp:
   tcp.settimeout(9)
   stage="TLS"
   ctx=ssl.create_default_context()
   ctx.set_alpn_protocols(["http/1.1"])
   with ctx.wrap_socket(tcp,server_hostname=host) as tls:
    if not tls.getpeercert():raise RuntimeError("NO_CERT")
    stage="HTTP"
    tls.sendall(("GET / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: MNEBYDNS-ReadOnly-Research/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
    data=tls.recv(1024)
    m=re.match(rb"HTTP/1\.[01] ([1-5][0-9]{2})",data)
    if not m:raise RuntimeError("HTTP_STATUS_INVALID")
    return {"host":host,"status":int(m.group(1)),"error":None}
 except Exception as exc:
  return {"host":host,"status":None,"error":stage+":"+type(exc).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
 print(json.dumps(list(pool.map(probe,hosts)),separators=(",",":")))
'''
def emit(tag,**kwargs):
    REPORT.mkdir(parents=True,exist_ok=True)
    entry={"event":tag, **kwargs}
    with (REPORT/"events.jsonl").open("a") as fp:
        fp.write(json.dumps(entry,sort_keys=True,ensure_ascii=False)+"\n")
    print("MNEBYDNS_BULK_EVENT="+json.dumps(entry,ensure_ascii=False),flush=True)

def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()

def selected_manifest():
    path=plan.OUTPUT/"eligible-manifest.tsv"
    records=[]
    for raw in path.read_text().splitlines():
        parts=raw.split("\t")
        if len(parts)!=2:
            raise RuntimeError("Malformed manifest")
        h=renderer.validate_domain(parts[0])
        ip=renderer.validated_public_ip(parts[1])
        records.append((h,ip))
    if len(records)!=len(set(h for h, _ in records)) or not 1<=len(records)<=102:
        raise RuntimeError("Invalid bulk manifest")
    return records

def atomic_update_sql(selected):
    values=",".join("('"+h+"','"+ip+"')" for h,ip in selected)
    n=len(selected)
    # The RAISE ensures that unexpected concurrent row changes roll back the
    # entire statement even if a subset was updated by UPDATE ... FROM.
    return (
        "DO $bulk$ DECLARE matched integer; modified integer; BEGIN "
        "SELECT count(*) INTO matched FROM dns_admin_domains d JOIN "
        "(VALUES "+values+") AS inputs(domain,ip) ON d.domain=inputs.domain "
        "WHERE d.product='Research 2026-11' AND d.status='PENDING'; "
        "IF matched<>"+str(n)+" THEN RAISE EXCEPTION 'BULK_DB_STALE_BEFORE_UPDATE'; END IF; "
        "UPDATE dns_admin_domains d SET status='ACTIVE', revision=revision+1,"
        "verified_origin_ip=inputs.ip::inet,applied_at=now(),confirmed_at=now(),updated_at=now(),"
        "last_error_code=NULL,canary_expires_at=NULL,canary_run_id=NULL "
        "FROM (VALUES "+values+") AS inputs(domain,ip) "
        "WHERE d.domain=inputs.domain AND d.product='Research 2026-11' "
        "AND d.status='PENDING'; GET DIAGNOSTICS modified=ROW_COUNT; "
        "IF modified<>"+str(n)+" THEN RAISE EXCEPTION 'BULK_DB_CAS_LOST'; END IF; "
        "END $bulk$;"
    )

def read_state(selected):
    names=",".join("'"+h+"'" for h,_ in selected)
    raw=owner.sql("SELECT domain||'|'||status||'|'||coalesce(verified_origin_ip::text,'') "
                  "FROM dns_admin_domains WHERE domain IN ("+names+") ORDER BY domain")
    result={}
    for line in raw.splitlines():
        parts=line.split("|")
        if len(parts)!=3 or parts[0] in result:
            raise RuntimeError("Unparseable owner status reconciliation")
        result[parts[0]]=(parts[1],parts[2])
    if set(result)!={h for h,_ in selected}:
        raise RuntimeError("MISSING_OWNER_STATUS_AFTER_COMMIT")
    return result

def status_class(selected):
    states=read_state(selected)
    if all(states[h][0]=="ACTIVE" and owner.pg_inet_host(states[h][1])==ip
           for h,ip in selected):
        return "ALL_ACTIVE"
    if all(states[h][0]=="PENDING" for h,ip in selected):
        return "ALL_PENDING"
    return "MIXED_UNSAFE"

def transfer_more(work, names):
    for f in names:
        if not Path(f).is_file():
            raise RuntimeError("Missing local staged resource")
        out=owner.cmd(["sshpass","-e","scp","-q","-o","ConnectTimeout=12",
            *owner.SSH_TRUST,"-o","LogLevel=ERROR",str(f),
            "root@"+owner.EDGE+":"+work+"/"+Path(f).name],
            password=os.environ["DE_PASS"],timeout=90)

def stage_and_verify(selected, raw_summary):
    run=os.environ["GITHUB_RUN_ID"]
    if not re.fullmatch(r"[1-9][0-9]{8,12}",run):
        raise RuntimeError("Invalid GitHub canary ID")
    work="/tmp/mnebydns-owner-domain-"+run
    base="/opt/mnebydns-owner-domain/"+run
    owner.RUNID=run
    owner.WORK=work
    owner.transfer_to_de()
    raw_core=plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")
    raw_nginx=plan.read_exact_remote("de","/etc/nginx/nginx.conf")
    if sha(raw_core)!=raw_summary["source_sha256"]["core"] or (
       sha(raw_nginx)!=raw_summary["source_sha256"]["nginx"]):
        raise RuntimeError("Source moved since mass preflight")
    c,n=raw_core,raw_nginx
    for host,ip in selected:
        c=renderer.core_add(c,host)
        n=renderer.nginx_add(n,host,ip)
    if sha(c)!=raw_summary["target_sha256"]["core"] or (
       sha(n)!=raw_summary["target_sha256"]["nginx"]):
        raise RuntimeError("Bulk target changed during preflight")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="mnebydns-bulk-") as tmp:
        folder=Path(tmp)
        (folder/"manifest.tsv").write_text("".join(h+"\t"+ip+"\n" for h,ip in selected))
        (folder/"expected.json").write_text(json.dumps(raw_summary,sort_keys=True))
        (folder/"dns.pilot").write_text(c)
        (folder/"nginx.pilot").write_text(n)
        for extra in ("mnebydns-bulk-stage-20261112.sh",
                      "mnebydns-bulk-remote-verify-20261112.py",
                      "mnebydns-bulk-compensate-20261112.sh"):
            (folder/extra).write_bytes((ROOT/"scripts"/extra).read_bytes())
        transfer_more(work,[folder/x for x in
            ("manifest.tsv","expected.json","dns.pilot","nginx.pilot",
             "mnebydns-bulk-stage-20261112.sh",
             "mnebydns-bulk-remote-verify-20261112.py",
             "mnebydns-bulk-compensate-20261112.sh")])
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Checkpoint moved before guarded stage")
    stage_command="bash "+shlex.quote(work+"/mnebydns-bulk-stage-20261112.sh")+" "+shlex.quote(work)+" "+run
    out=owner.ssh("de",stage_command,180)
    if "MNEBYDNS_BULK_CANARY_LIVE="+run not in out:
        raise RuntimeError("No independent rollback timer confirmation")
    if plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")!=c or (
       plan.read_exact_remote("de","/etc/nginx/nginx.conf")!=n):
        raise RuntimeError("Staged pilot bytes mismatch")
    emit("STAGED",count=len(selected),run=run)
    return run,base,work

def validate_dns_one(host):
    code, ips=owner.dns_q(host,1)
    if code!=0 or ips!=[owner.EDGE]:
        return host,"A_REWRITE_MISMATCH"
    for kind in (28,5,64,65):
        rcode, other=owner.dns_q(host,kind)
        if rcode!=0 or other:
            return host,"ALT_DNS_RR_NOT_SUPPRESSED_"+str(kind)
    return host,"PASS"

def verify_live(selected):
    hosts=[h for h,_ in selected]
    owner.oracle_canary_check(hosts[0],True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        dns_verdicts=dict(pool.map(validate_dns_one,hosts))
    problems={h:why for h,why in dns_verdicts.items() if why!="PASS"}
    payload=base64.b64encode(json.dumps(hosts).encode()).decode()
    remote="python3 -c "+shlex.quote(RU_HTTPS)+" "+shlex.quote(payload)+" "+owner.EDGE
    raw=owner.ssh("ru",remote,480)
    outcomes=json.loads(raw)
    if not isinstance(outcomes,list) or len(outcomes)!=len(hosts):
        raise RuntimeError("Incomplete public HTTPS bulk response")
    if {x.get("host") for x in outcomes}!=set(hosts):
        raise RuntimeError("Missing or repeated public edge hostname")
    for x in outcomes:
        if x.get("status") is None or not 200<=x["status"]<400:
            problems[x["host"]]="EDGE_HTTPS_"+str(x.get("status") or x.get("error"))
    for host in hosts:
        emit("HOST_TEST",domain=host,
             dns=dns_verdicts[host],
             edge_status=next(x["status"] for x in outcomes if x["host"]==host),
             eligible_for_commit=host not in problems)
    owner.oracle_canary_check(hosts[-1],True)
    batch.capacity()
    if problems:
        raise RuntimeError("BULK_HOST_FAILURES count="+str(len(problems))+
                           " first="+",".join(list(problems)[:5]))
    emit("ALL_HOSTS_EDGE_AND_DOT_OK",count=len(hosts))
    return outcomes

def run_deploy():
    if os.environ.get("GITHUB_EVENT_NAME")!="push" or (
       os.environ.get("GITHUB_REF")!="refs/heads/main"):
        raise RuntimeError("Production bulk deploy only from reviewed main push")
    # Requires explicit reviewed switch disabled for old 3-per-cycle automation.
    if batch.enabled():
        raise RuntimeError("OLD_3_DOMAIN_CRON_STILL_ENABLED")
    plan.live_plan()
    summary=json.loads((plan.OUTPUT/"summary.json").read_text())
    selected=selected_manifest()
    if summary["eligible"]!=len(selected) or len(selected)<75:
        raise RuntimeError("TOO_FEW_VERIFIED_BULK_ROUTES")
    if summary["decisions"].get("EXCLUDE_ROUTE_COLLISION",0)>0:
        raise RuntimeError("EXISTING_CONFIG_OVERLAP_REQUIRES_REVIEW")
    if summary["decisions"].get("EXCLUDE_UNVERIFIED_DIFFERENTIAL",0)>10:
        raise RuntimeError("TOO_MANY_NEWLY_UNVERIFIED_CANDIDATES")
    batch.ensure_quiet()
    batch.capacity()
    if not all(batch.table().get(h)==("PENDING",batch.PRODUCT,"") for h,_ in selected):
        raise RuntimeError("Owner status changed between preflight and stage")
    emit("PREFLIGHT_OK",count=len(selected),excluded=summary["decisions"])
    run=None
    committed=False
    try:
        run,base,work=stage_and_verify(selected,summary)
        verify_live(selected)
        current_rows=batch.table()
        if not all(current_rows.get(h,("","",""))[0]=="PENDING" and
                   current_rows.get(h,("","",""))[1]==batch.PRODUCT for h,_ in selected):
            raise RuntimeError("Bulk PENDING state changed during canary")
        output=owner.ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+shlex.quote(base),80)
        if "owner_domain_confirmed_stable=true" not in output and (
           "owner_domain_already_confirmed=true" not in output):
            raise RuntimeError("Checkpoint was not committed")
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("Committed checkpoint not stable")
        committed=True
        emit("CHECKPOINT_COMMITTED",count=len(selected))
        try:
            owner.sql(atomic_update_sql(selected))
        except Exception as exc:
            emit("DB_COMMIT_ERROR",error=type(exc).__name__)
            # Reconcile first: a lost SSH reply must not undo a valid DB commit.
            state=status_class(selected)
            if state!="ALL_ACTIVE":
                raise RuntimeError("BULK_DB_UNCERTAIN_"+state) from exc
        if status_class(selected)!="ALL_ACTIVE":
            raise RuntimeError("BULK_DATABASE_NOT_ALL_ACTIVE")
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("POST_COMMIT_CHECKPOINT_DRIFT")
        emit("BULK_ACTIVE",count=len(selected))
        (REPORT/"report.md").write_text("# Bulk DNS activation\n\n"+
            str(len(selected))+" exact-host routes are ACTIVE in PostgreSQL and live checkpoint.\n"+
            "The checks cover server HTTP/TLS/DoT, NOT end-user app sessions.\n")
    except Exception as exc:
        emit("BULK_ABORT",error_class=type(exc).__name__,reason=str(exc)[:400],
             confirmed_checkpoint=committed)
        if run:
            # The existing owner controller may promote the checkpoint before
            # writing its confirmed sentinel or returning SSH output. Never
            # describe that crash window as an ordinary verified rollback.
            actually_confirmed = committed or owner.is_confirmed(run)
            if actually_confirmed:
                # An all-or-none SQL failure leaves all rows PENDING; compensate
                # the committed checkpoint explicitly. Unknown/mixed states
                # must not be overwritten automatically.
                state = status_class(selected)
                if state == "ALL_PENDING":
                    command = ("bash " +
                        shlex.quote(work+"/mnebydns-bulk-compensate-20261112.sh") +
                        " " + shlex.quote(base))
                    out = owner.ssh("de",command,120)
                    if "MNEBYDNS_BULK_COMPENSATING_REVERT_VERIFIED=true" not in out or (
                       not owner.live_checkpoint_unchanged()):
                        raise RuntimeError("CRITICAL_BULK_COMPENSATION_UNVERIFIED") from exc
                    emit("COMPENSATION_VERIFIED",count=len(selected))
                else:
                    emit("INCIDENT_MANUAL_RECONCILIATION",db_state=state)
            else:
                owner.rollback_or_unchanged(run)
                if not owner.live_checkpoint_unchanged():
                    raise RuntimeError("CRITICAL_BULK_ROLLBACK_UNVERIFIED") from exc
                emit("ROLLBACK_VERIFIED",count=len(selected))
        raise

def offline_test():
    for host in ("example.org","hello.world"):
        renderer.validate_domain(host)
    sql=atomic_update_sql([("example.org","93.184.215.14")])
    assert "BULK_DB_CAS_LOST" in sql and "GET DIAGNOSTICS" in sql
    assert "PENDING" in sql and "ACTIVE" in sql
    assert "END $bulk$" in sql
    assert "max_workers=8" in RU_HTTPS and "ctx.wrap_socket" in RU_HTTPS
    compile(RU_HTTPS,"<RU HTTPS probe>","exec")
    print("MNEBYDNS_BULK_DEPLOY_OFFLINE=PASS")

if __name__=="__main__":
    arg=argparse.ArgumentParser()
    arg.add_argument("mode",choices=("self-test","deploy"))
    args=arg.parse_args()
    offline_test() if args.mode=="self-test" else run_deploy()
