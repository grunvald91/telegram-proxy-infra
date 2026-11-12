#!/usr/bin/env python3
"""Explicitly requested exact-host activation: Oracle Cloud, Cisco ID, Code Browser.

Uses the existing single-host independently timed owner canary and checkpoint
promotion; no wildcard routes, no new proxy system, no rewriting other owners.
The direct RU HTTP 403/451 classification is informational: this is an
owner-authorized exact host request, including hosts with RU TCP timeout.
Actual public RU -> DE HTTPS and trusted certificate are REQUIRED before
promoting any requested host. Never marks a failed test as ACTIVE.
"""
from __future__ import annotations
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "requested-three-results"
TARGETS = (
    ("cloud.oracle.com", "Oracle"),
    ("id.cisco.com", "Research 2026-11"),
    ("codebrowser.dev", "Research 2026-11"),
)
BATCH = ROOT / "scripts/mnebydns-batch-108-canary-20261112.py"
SCANNER = ROOT / "scripts/mnebydns-geoblock-stage2-probe-20261111.py"

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    if not spec or not spec.loader:raise RuntimeError("Missing reviewed controller")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

batch=load("on_demand_owner_batch",BATCH)
scanner=load("on_demand_ru_de_scanner",SCANNER)
owner=batch.owner

def emit(event, **info):
    OUTPUT.mkdir(mode=0o700,exist_ok=True)
    line=dict(timestamp_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
              event=event,**info)
    with (OUTPUT / "events.jsonl").open("a") as f:
        f.write(json.dumps(line,sort_keys=True,ensure_ascii=False)+"\n")
    print("REQUESTED_THREE="+json.dumps(line,sort_keys=True,ensure_ascii=False),flush=True)

def states():
    rows=batch.table()
    for domain,product in TARGETS:
        if domain not in rows:raise RuntimeError("Exact domain DB row is absent: "+domain)
        state,actual_product,last_error=rows[domain]
        if actual_product!=product:raise RuntimeError("Domain ownership changed: "+domain)
        if state not in ("PENDING","ACTIVE"):
            raise RuntimeError("Unsafe preexisting domain status: "+domain+"/"+state)
        if state=="ACTIVE" and last_error:
            raise RuntimeError("ACTIVE domain has unresolved health error: "+domain)
    return rows

def status(domain,product):
    out=owner.sql("SELECT status FROM dns_admin_domains WHERE domain='"+domain+
                  "' AND product='"+product+"'").strip()
    if out not in ("PENDING","APPLY_REQUESTED","PROBING","CANARY",
                   "CONFIRM_REQUESTED","CONFIRMING","ACTIVE","FAILED"):
        raise RuntimeError("Unknown database state: "+domain)
    return out

def task_for(domain,expected):
    item=owner.get_task()
    if not item or item["domain"]!=domain or item["status"]!=expected:
        raise RuntimeError("Concurrent owner task selected; refuse mutation")
    return item

def origin_after_apply(domain,product):
    value=owner.sql("SELECT coalesce(verified_origin_ip::text,'') FROM dns_admin_domains "+
                    "WHERE domain='"+domain+"' AND product='"+product+
                    "' AND status='CANARY'").strip()
    return owner.pg_inet_host(value)

def mark_failed_after_verified_rollback(domain,product,reason,run):
    # Failures never leave a live pilot or an uncertain claim of ACTIVE.
    state=status(domain,product)
    if state=="FAILED":
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("FAILED_STATUS_WITH_LIVE_DRIFT")
        emit("FAILED_SAFE",domain=domain,reason=reason)
        return
    if state in ("CANARY","PROBING","APPLY_REQUESTED"):
        owner.rollback_or_unchanged(run)
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("ROLLBACK_NOT_VERIFIED")
        owner.oracle_canary_check(domain,False)
        changed=owner.sql(
            "UPDATE dns_admin_domains SET status='FAILED',"
            "last_error_code='ON_DEMAND_ROUTE_HTTPS_FAILED',"
            "canary_expires_at=NULL,updated_at=now() "
            "WHERE domain='"+domain+"' AND product='"+product+
            "' AND status IN ('CANARY','PROBING','APPLY_REQUESTED') RETURNING domain")
        if changed!=domain:raise RuntimeError("FAILED_STATE_CAS_NOT_VERIFIED")
        emit("ROLLED_BACK",domain=domain,reason=reason)
        return
    # A promoted stable checkpoint must not be mistaken for unconfirmed
    # pilot; service owner must reconcile explicitly before further work.
    raise RuntimeError("CRITICAL_CONFIRM_OR_DB_STATE_UNCERTAIN_"+domain+"_"+state)

def offline_test():
    assert len(TARGETS)==3 and len({d for d,_ in TARGETS})==3
    for d,p in TARGETS:
        assert owner._render.validate_domain(d)==d
        assert p in ("Oracle","Research 2026-11")
    assert batch.MAX_PER_RUN>=3
    assert all(re.fullmatch(r"[a-z0-9.-]+",d) for d,_ in TARGETS)
    print("ON_DEMAND_THREE_OFFLINE=PASS",flush=True)

def deploy():
    if os.environ.get("GITHUB_EVENT_NAME")!="push" or (
       os.environ.get("GITHUB_REF")!="refs/heads/main"):
        raise RuntimeError("Production activation must run from reviewed main push")
    if not os.environ.get("RU_PASS") or not os.environ.get("DE_PASS"):
        raise RuntimeError("Missing pinned SSH credentials")
    batch.ensure_quiet()
    batch.capacity()
    rows=states()
    pending=[d for d,p in TARGETS if rows[d][0]=="PENDING"]
    if not pending:
        emit("ALREADY_ALL_ACTIVE")
        return
    # Fresh strict TLS/SNI origin resolution and HTTP GET / from DE; RU
    # direct outcome is diagnostic only for these explicitly requested names.
    targets=[{"host":d} for d in pending]
    de=scanner.via_ssh("DE",targets)
    ru=scanner.via_ssh("RU",[{"host":d,"origin_ipv4":de[d].get("origin_ipv4")}
                             for d in pending])
    eligible={}
    for domain,product in TARGETS:
        if domain not in pending:continue
        foreign=de[domain]; russian=ru[domain]
        ip=foreign.get("origin_ipv4")
        verified=(foreign.get("certificate_verified") is True and
                  type(foreign.get("http_status")) is int and
                  200<=foreign["http_status"]<400)
        if verified:
            owner._render.validated_public_ip(ip)
            eligible[domain]=ip
        emit("ORIGIN_PREFLIGHT",domain=domain,product=product,
             foreign_http=foreign.get("http_status"),foreign_tls_verified=verified,
             ru_http=russian.get("http_status"),ru_state=russian.get("state"),
             can_attempt=verified)
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Production checkpoint changed during preflight")
    for number,(domain,product) in enumerate(TARGETS,1):
        rows=states()
        if rows[domain][0]=="ACTIVE":
            emit("SKIP_ALREADY_ACTIVE",domain=domain)
            continue
        if domain not in eligible:
            emit("NOT_ELIGIBLE_DE_TLS",domain=domain)
            continue
        batch.ensure_quiet()
        batch.capacity()
        phase=batch.set_phase(number)
        emit("CANARY_BEGIN",domain=domain,run_id=phase)
        changed=owner.sql(
            "UPDATE dns_admin_domains SET status='APPLY_REQUESTED',"
            "revision=revision+1,updated_at=now(),"
            "canary_run_id=NULL,canary_expires_at=NULL,last_error_code=NULL "
            "WHERE domain='"+domain+"' AND product='"+product+
            "' AND status='PENDING' RETURNING domain")
        if changed!=domain:raise RuntimeError("Owner row CAS lost")
        try:
            owner.apply(task_for(domain,"APPLY_REQUESTED"))
            if status(domain,product)!="CANARY":
                raise RuntimeError("OWNER_CANARY_NOT_ESTABLISHED")
            origin=origin_after_apply(domain,product)
            de_http=batch.http_probe("de",domain,origin)
            edge_http=batch.http_probe("ru",domain,owner.EDGE)
            if not (200<=de_http<400 and 200<=edge_http<400):
                raise RuntimeError("EXACT_HOST_PUBLIC_EDGE_HTTP_NOT_SUCCESSFUL")
            owner.oracle_canary_check(domain,True)
            batch.capacity()
            emit("PUBLIC_ROUTE_VERIFIED",domain=domain,de_http=de_http,
                 ru_via_de_http=edge_http,pinned_origin=origin)
            changed=owner.sql(
                "UPDATE dns_admin_domains SET status='CONFIRM_REQUESTED',"
                "updated_at=now() WHERE domain='"+domain+
                "' AND product='"+product+"' AND status='CANARY' "
                "AND canary_run_id="+phase+" RETURNING domain")
            if changed!=domain:
                raise RuntimeError("CANARY_TO_CONFIRM_CAS_REJECTED")
            owner.confirm(task_for(domain,"CONFIRM_REQUESTED"))
            if status(domain,product)!="ACTIVE" or not owner.live_checkpoint_unchanged():
                raise RuntimeError("ACTIVE_CONFIRMATION_UNVERIFIED")
            owner.oracle_canary_check(domain,True)
            emit("ACTIVE_VERIFIED",domain=domain,pinned_origin=origin,
                 ru_via_de_http=edge_http)
        except Exception as exc:
            emit("CANARY_FAILED",domain=domain,error_type=type(exc).__name__,
                 reason=str(exc)[:160])
            # For a failed/no-op canary the existing owner canary might
            # already have completed its own rollback and FAILED status.
            mark_failed_after_verified_rollback(domain,product,
                                                type(exc).__name__,phase)
            # Continue only if the previous stable state was proven restored.
            batch.ensure_quiet()
            continue
    results=states()
    items=[dict(domain=d,product=p,status=results[d][0],
                last_error=results[d][2]) for d,p in TARGETS]
    (OUTPUT/"final-status.json").write_text(json.dumps(items,indent=2,ensure_ascii=False)+"\n")
    emit("COMPLETE",active=sum(x["status"]=="ACTIVE" for x in items),
         failed=sum(x["status"]=="FAILED" for x in items),
         pending=sum(x["status"]=="PENDING" for x in items),outcomes=items)

if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("self-test","deploy"):
        raise SystemExit("usage: self-test|deploy")
    offline_test() if sys.argv[1]=="self-test" else deploy()
