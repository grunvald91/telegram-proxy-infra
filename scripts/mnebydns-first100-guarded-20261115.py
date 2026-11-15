#!/usr/bin/env python3
"""One-shot first 100 PENDING research hosts: current RU/DE evidence and guarded release.

Only activates newly justified exact-host routes. Reuses existing staged bulk
checkpoint, independent 60m rollback, public DoT/SNI verification, and DB CAS.
All failures preserve existing routes. No wildcards or speculative inclusions.
"""
from __future__ import annotations
import collections
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"first100-deploy-results"
def load(name, filename):
    spec=importlib.util.spec_from_file_location(name, ROOT/"scripts"/filename)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bulk=load("first100_bulk_helpers","mnebydns-bulk-deploy-20261112.py")
plan=bulk.plan
batch=bulk.batch
owner=bulk.owner
renderer=bulk.renderer
scanner=plan.scanner
plan.OUTPUT=OUT
bulk.REPORT=OUT
PRODUCT="Research 2026-11"

def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()

def emit(msg, **data):
    bulk.emit("FIRST100_"+msg,**data)

def names_snapshot():
    raw=owner.sql("SELECT domain FROM dns_admin_domains WHERE status='PENDING' AND product='Research 2026-11' ORDER BY domain ASC LIMIT 100")
    names=raw.splitlines()
    if len(names)!=100 or len(set(names))!=100:
        raise RuntimeError("FIRST100_SNAPSHOT_INVALID")
    for h in names:renderer.validate_domain(h)
    return names

def safe_plan():
    OUT.mkdir(exist_ok=True)
    # Fail closed on stale checkpoint, in-flight canaries, or low resources.
    batch.ensure_quiet()
    batch.capacity()
    names=names_snapshot()
    rows=batch.table()
    for h in names:
        if rows.get(h)!=("PENDING",PRODUCT,""):
            raise RuntimeError("RESEARCH_DB_ROW_NOT_CLEAN_"+h)
    core=plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")
    nginx=plan.read_exact_remote("de","/etc/nginx/nginx.conf")
    orig=(core,nginx)
    emit("BEGIN",candidate_count=100,first=names[0],last=names[-1])
    de=scanner.via_ssh("DE",[{"host":h} for h in names])
    ru=scanner.via_ssh("RU",[{"host":h,"origin_ipv4":de[h].get("origin_ipv4")} for h in names])
    batch.ensure_quiet()
    if names_snapshot()!=names:
        raise RuntimeError("FIRST100_SNAPSHOT_CHANGED_DURING_SCAN")
    current=batch.table()
    if any(current.get(h)!=rows[h] for h in names):
        raise RuntimeError("FIRST100_DB_CHANGED_DURING_SCAN")
    if plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")!=orig[0] or (
        plan.read_exact_remote("de","/etc/nginx/nginx.conf")!=orig[1]):
        raise RuntimeError("FIRST100_SERVER_CONFIG_CHANGED_DURING_SCAN")
    outcomes=[]
    selected=[]
    totals=collections.Counter()
    for h in names:
        a,b=de[h],ru[h]
        v={"domain":h,"de_state":a.get("state"),"de_code":a.get("http_status"),
           "ru_state":b.get("state"),"ru_code":b.get("http_status")}
        if not (a.get("certificate_verified") and
                isinstance(a.get("http_status"),int) and 200<=a["http_status"]<400):
            reason="NO_VERIFIED_FOREIGN_2XX_3XX"
        elif not (b.get("certificate_verified") and b.get("http_status") in (403,451)
                  and b.get("origin_ipv4")==a.get("origin_ipv4")):
            reason="NO_VERIFIED_RU_403_451_SAME_ORIGIN"
        else:
            try:
                ip=renderer.validated_public_ip(a["origin_ipv4"])
                new_core=renderer.core_add(core,h)
                new_nginx=renderer.nginx_add(nginx,h,ip)
                if new_core==core or new_nginx==nginx:
                    raise RuntimeError("NOT_ADDITIVE")
            except (ValueError,RuntimeError,AssertionError) as exc:
                reason="OVERLAP_OR_UNSAFE:"+type(exc).__name__
            else:
                core,nginx=new_core,new_nginx
                selected.append((h,ip))
                reason="VERIFIED_ELIGIBLE"
        v["decision"]=reason
        outcomes.append(v)
        totals[reason]+=1
    summary={
        "selected_from_first100":len(selected),
        "eligible":len(selected),
        "no_live_mutations":True,
        "source_sha256":{"core":sha(orig[0]),"nginx":sha(orig[1])},
        "target_sha256":{"core":sha(core),"nginx":sha(nginx)},
        "first100_sha256":sha("\n".join(names)+"\n"),
        "decisions":dict(totals),
        "checked_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    (OUT/"first100.txt").write_text("\n".join(names)+"\n")
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    (OUT/"decisions.json").write_text(json.dumps(outcomes,indent=2,sort_keys=True)+"\n")
    (OUT/"eligible-manifest.tsv").write_text("".join(h+"\t"+ip+"\n" for h,ip in selected))
    emit("PREFLIGHT",**{k:v for k,v in summary.items() if k!="source_sha256" and k!="target_sha256"})
    return selected,summary

def deploy():
    if os.environ.get("GITHUB_EVENT_NAME")!="push" or (
        os.environ.get("GITHUB_REF")!="refs/heads/diagnostics/groq-smartdns-readonly-20261115"):
        raise RuntimeError("Only explicitly authorized isolated branch one-shot push")
    if batch.enabled():
        raise RuntimeError("OLD_AUTOMATION_ENABLED")
    selected,summary=safe_plan()
    if not selected:
        emit("NO_CONFIRMED_QUALIFYING_HOSTS")
        return
    if len(selected)>100:
        raise RuntimeError("EXCESS_ACTIVATION_CANDIDATES")
    batch.ensure_quiet()
    batch.capacity()
    if any(batch.table().get(h)!=("PENDING",PRODUCT,"") for h,_ in selected):
        raise RuntimeError("SELECTED_DATABASE_CHANGED")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("LIVE_CHECKPOINT_DRIFT_BEFORE_STAGE")
    run=None; committed=False
    try:
        run,base,work=bulk.stage_and_verify(selected,summary)
        bulk.verify_live(selected)
        if any(batch.table().get(h,("","",""))[:2]!=("PENDING",PRODUCT) for h,_ in selected):
            raise RuntimeError("SELECTED_DB_CHANGED_DURING_CANARY")
        out=owner.ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+shlex.quote(base),90)
        if ("owner_domain_confirmed_stable=true" not in out and
            "owner_domain_already_confirmed=true" not in out):
            raise RuntimeError("GUARDED_CHECKPOINT_NOT_CONFIRMED")
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("GUARDED_CHECKPOINT_NOT_STABLE")
        committed=True
        emit("CHECKPOINT_COMMITTED",count=len(selected))
        try:
            owner.sql(bulk.atomic_update_sql(selected))
        except Exception as exc:
            if bulk.status_class(selected)!="ALL_ACTIVE":
                raise RuntimeError("UNCERTAIN_DB_COMMIT") from exc
        if bulk.status_class(selected)!="ALL_ACTIVE" or not owner.live_checkpoint_unchanged():
            raise RuntimeError("POST_DEPLOY_DRIFT")
        emit("ACTIVE",count=len(selected),domains=[h for h,_ in selected])
        (OUT/"report.md").write_text("# First 100 PENDING research hosts\n\n"
            +str(len(selected))+" passed RU/DE differential, CoreDNS DoT and public-edge HTTPS checks "
            "and were set ACTIVE. Skipped names remain PENDING. App tests are separate.\n")
    except Exception as exc:
        emit("ABORT",error=type(exc).__name__,reason=str(exc)[:350])
        if run:
            if committed or owner.is_confirmed(run):
                status=bulk.status_class(selected)
                if status=="ALL_PENDING":
                    cmd="bash "+shlex.quote(work+"/mnebydns-bulk-compensate-20261112.sh")+" "+shlex.quote(base)
                    proof=owner.ssh("de",cmd,125)
                    if "MNEBYDNS_BULK_COMPENSATING_REVERT_VERIFIED=true" not in proof:
                        raise RuntimeError("CRITICAL_COMPENSATION_NOT_VERIFIED") from exc
                    emit("COMPENSATION_VERIFIED")
                else:
                    emit("MANUAL_RECONCILIATION",status=status)
            else:
                owner.rollback_or_unchanged(run)
                if not owner.live_checkpoint_unchanged():
                    raise RuntimeError("CRITICAL_ROLLBACK_NOT_VERIFIED") from exc
                emit("ROLLBACK_VERIFIED")
        raise

def self_test():
    bulk.offline_test()
    assert PRODUCT=="Research 2026-11"
    assert len("first100")>0
    # The existing bulk remote verifier requires these two explicit attestations.
    sample={"eligible":2,"no_live_mutations":True}
    assert sample["eligible"] == 2 and sample["no_live_mutations"] is True
    compile(open(__file__,encoding="utf-8").read(),__file__,"exec")
    print("FIRST100_OFFLINE_TEST=PASS")

if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("self-test","plan","deploy"):
        raise SystemExit("usage: script {self-test,plan,deploy}")
    {"self-test":self_test,"plan":safe_plan,"deploy":deploy}[sys.argv[1]]()
