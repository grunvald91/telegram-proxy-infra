#!/usr/bin/env python3
"""Owner-authorised priority Groq.com exact-host guarded production change.

Fresh foreign certificate verification, additive only, independent 60m
rollback, public RU188 edge HTTPS and DoT validation, fail-closed all-or-none.
No wildcards; no undocumented localhost/private origin routing.
"""
from __future__ import annotations
import collections
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"groq3-results"
TARGETS=("groq.com","chat.groq.com","console.groq.com")
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/file)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj)
    return obj
bulk=load("groq3_bulk","mnebydns-bulk-deploy-20261112.py")
plan=bulk.plan
owner=bulk.owner
batch=bulk.batch
scanner=plan.scanner
render=bulk.renderer
plan.OUTPUT=OUT
bulk.REPORT=OUT
def emit(event,**values):
    bulk.emit("GROQ_"+event,**values)
def sha(s):return hashlib.sha256(s.encode()).hexdigest()
def preflight():
    OUT.mkdir(exist_ok=True)
    batch.ensure_quiet()
    batch.capacity()
    # Guard established ingress and baseline from the actual public DoT service.
    for host in ("gemini.google.com","claude.ai","grok.com","x.com","chatgpt.com"):
        rc,ip=owner.dns_q(host,1)
        if rc!=0 or ip!=[owner.RU]:raise RuntimeError("STABLE_DNS_DRIFT_"+host)
    rows=batch.table()
    pending=[]
    result={}
    for h in TARGETS:
        row=rows.get(h,("","",""))
        if row[1]!="Research 2026-11" or row[0] not in ("PENDING","ACTIVE"):
            raise RuntimeError("UNEXPECTED_GROQ_DB_ROW_"+h)
        if row[2]:raise RuntimeError("NONEMPTY_GROQ_DB_ERROR_"+h)
        if row[0]=="PENDING":pending.append(h)
        else:result[h]="ALREADY_ACTIVE"
    emit("BEGIN",pending=pending,states={h:rows[h][0] for h in TARGETS})
    if pending:
        de=scanner.via_ssh("DE",[{"host":h} for h in pending])
        ru=scanner.via_ssh("RU",[{"host":h,"origin_ipv4":de[h].get("origin_ipv4")} for h in pending])
    else:de=ru={}
    batch.ensure_quiet()
    if any(batch.table()[h]!=rows[h] for h in TARGETS):raise RuntimeError("GROQ_STATE_CHANGED")
    core=plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")
    nginx=plan.read_exact_remote("de","/etc/nginx/nginx.conf")
    base_core,base_nginx=core,nginx
    eligible=[]
    for h in pending:
        a,b=de[h],ru[h]
        if a.get("certificate_verified") is not True or type(a.get("http_status")) is not int or not (200<=a["http_status"]<400):
            result[h]="FOREIGN_ORIGIN_HTTPS_UNVERIFIED"
            continue
        try:
            ip=render.validated_public_ip(a["origin_ipv4"])
            new_core=render.core_add(core,h)
            new_nginx=render.nginx_add(nginx,h,ip)
            if new_core==core or new_nginx==nginx:raise RuntimeError("NON_ADDITIVE")
            core,nginx=new_core,new_nginx
        except (ValueError,RuntimeError,AssertionError) as exc:
            result[h]="OVERLAP_OR_INVALID_"+type(exc).__name__+":"+str(exc)[:100]
            continue
        result[h]="ELIGIBLE"
        eligible.append((h,ip))
    summary={"eligible":len(eligible),"no_live_mutations":True,
             "source_sha256":{"core":sha(base_core),"nginx":sha(base_nginx)},
             "target_sha256":{"core":sha(core),"nginx":sha(nginx)},
             "checked_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
             "decisions":dict(collections.Counter(result.values()))}
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n")
    (OUT/"per-domain.json").write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    (OUT/"eligible-manifest.tsv").write_text("".join(h+"\t"+ip+"\n" for h,ip in eligible))
    emit("PREFLIGHT",summary=summary,hosts=[h for h,_ in eligible])
    return eligible,summary
def deploy():
    if os.environ.get("GITHUB_EVENT_NAME")!="push" or (
         os.environ.get("GITHUB_REF")!="refs/heads/ops/mnebydns-groq-priority-20261115"):
        raise RuntimeError("UNAUTHORISED_GROQ_DEPLOY_REF")
    if batch.enabled():raise RuntimeError("CONCURRENT_LEGACY_BULK_ENABLED")
    selected,summary=preflight()
    if not selected:
        emit("NO_VERIFIED_NEW_TARGETS")
        return
    # Safe transaction: after confirm, DB must commit atomically or compensate.
    batch.ensure_quiet()
    batch.capacity()
    run=None;committed=False
    try:
        run,base,work=bulk.stage_and_verify(selected,summary)
        bulk.verify_live(selected)
        for h,_ in selected:
            if batch.table().get(h,("","",""))[:2]!=("PENDING","Research 2026-11"):
                raise RuntimeError("SELECTED_GROQ_DB_CHANGED")
        out=owner.ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+shlex.quote(base),90)
        if "owner_domain_confirmed_stable=true" not in out and "owner_domain_already_confirmed=true" not in out:
            raise RuntimeError("GROQ_CHECKPOINT_NOT_CONFIRMED")
        if not owner.live_checkpoint_unchanged():raise RuntimeError("GROQ_CHECKPOINT_DRIFT")
        committed=True
        emit("CHECKPOINT_COMMITTED",count=len(selected))
        try:
            owner.sql(bulk.atomic_update_sql(selected))
        except Exception as exc:
            if bulk.status_class(selected)!="ALL_ACTIVE":raise RuntimeError("GROQ_DB_COMMIT_UNCERTAIN") from exc
        if bulk.status_class(selected)!="ALL_ACTIVE":raise RuntimeError("GROQ_NOT_ALL_ACTIVE")
        if not owner.live_checkpoint_unchanged():raise RuntimeError("GROQ_POST_DEPLOY_DRIFT")
        emit("ACTIVE",count=len(selected),domains=[h for h,_ in selected])
    except Exception as exc:
        emit("ABORT",error=type(exc).__name__,reason=str(exc)[:300])
        if run:
            if committed or owner.is_confirmed(run):
                if bulk.status_class(selected)=="ALL_PENDING":
                    cmd="bash "+shlex.quote(work+"/mnebydns-bulk-compensate-20261112.sh")+" "+shlex.quote(base)
                    proof=owner.ssh("de",cmd,125)
                    if "MNEBYDNS_BULK_COMPENSATING_REVERT_VERIFIED=true" not in proof:
                        raise RuntimeError("CRITICAL_GROQ_COMPENSATION_UNVERIFIED") from exc
                    emit("COMPENSATION_VERIFIED")
                else:emit("MANUAL_RECONCILE",status=bulk.status_class(selected))
            else:
                owner.rollback_or_unchanged(run)
                if not owner.live_checkpoint_unchanged():
                    raise RuntimeError("CRITICAL_GROQ_ROLLBACK_UNVERIFIED") from exc
                emit("ROLLBACK_VERIFIED")
        raise
def selftest():
    bulk.offline_test()
    assert len(TARGETS)==3 and len(set(TARGETS))==3
    assert render.DNS_INGRESS==owner.RU and owner.RU!=owner.EDGE
    for h in TARGETS:render.validate_domain(h)
    print("GROQ3_SELFTEST=PASS",flush=True)
if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("selftest","deploy"):raise SystemExit("usage selftest|deploy")
    {"selftest":selftest,"deploy":deploy}[sys.argv[1]]()
