#!/usr/bin/env python3
"""One-off guarded follow-up of 13 original first100 sites with Russian TCP/TLS errors.

All routing tests are fresh. Uses the same independently timed staged
rollback, exact-host rendering, DoT and RU->DE HTTPS checks as the successful
first100 release. No route changes on direct-available or unverified sites.
"""
from __future__ import annotations
import collections
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("first100_guarded_reuse",HERE/"mnebydns-first100-guarded-20261115.py")
first=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(first)
batch=first.batch
owner=first.owner
renderer=first.renderer
scanner=first.scanner
plan=first.plan
OUT=first.OUT
HOSTS=(
 "account.mongodb.com","alberta.ca","analog.com","ansys.com","arduino.cc",
 "avira.com","axiomtek.com","badoo.com","badoocdn.com","bluehost.com",
 "bosch.de","bumble.com","census.gov",
)
def sha(s):return hashlib.sha256(s.encode()).hexdigest()
def plan_ru_errors():
    OUT.mkdir(exist_ok=True)
    batch.ensure_quiet()
    batch.capacity()
    names=list(HOSTS)
    if len(names)!=13 or len(set(names))!=13:raise RuntimeError("FIXED_TCP13_INVENTORY_INVALID")
    for host in names:renderer.validate_domain(host)
    # Fail closed if legacy DE-only edge is accidentally restored.
    for host in ("gemini.google.com","claude.ai","grok.com","x.com","www.tiktok.com","chatgpt.com"):
        rc,ips=owner.dns_q(host,1)
        if rc!=0 or ips!=[owner.RU]:
            raise RuntimeError("RU188_STABLE_DNS_CHANGED_"+host)
    rows=batch.table()
    for host in names:
        status,product,error=rows.get(host,("","",""))
        if product!="Research 2026-11" or status not in ("PENDING","ACTIVE"):
            raise RuntimeError("FIXED_DOMAIN_OWNERSHIP_CHANGED_"+host)
    pending=[host for host in names if rows[host][0]=="PENDING" and not rows[host][2]]
    core=plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")
    nginx=plan.read_exact_remote("de","/etc/nginx/nginx.conf")
    start_core,start_nginx=core,nginx
    first.emit("RU_TCP_FOLLOWUP_BEGIN",targets=len(names),pending=len(pending))
    if pending:
        de=scanner.via_ssh("DE",[{"host":h} for h in pending])
        ru=scanner.via_ssh("RU",[{"host":h,"origin_ipv4":de[h].get("origin_ipv4")} for h in pending])
    else:
        de=ru={}
    batch.ensure_quiet()
    if any(batch.table().get(h)!=rows[h] for h in names):
        raise RuntimeError("STATE_MOVED_DURING_TCP13_PROBE")
    if (plan.read_exact_remote("de","/opt/mnebydns-dot/Corefile")!=start_core or
        plan.read_exact_remote("de","/etc/nginx/nginx.conf")!=start_nginx):
        raise RuntimeError("POLICY_CHANGED_DURING_TCP13_PROBE")
    selected=[]
    statuses={}
    for host in names:
        if rows[host][0]=="ACTIVE":
            statuses[host]="ALREADY_ACTIVE"
            continue
        if host not in pending:
            statuses[host]="PENDING_WITH_ERROR_REQUIRES_MANUAL_REVIEW"
            continue
        a,b=de[host],ru[host]
        foreign_ok=(
            a.get("certificate_verified") is True
            and type(a.get("http_status")) is int
            and 200<=a["http_status"]<400)
        russian_error=b.get("state") in ("TCP_ERROR","TLS_ERROR") and b.get("http_status") is None
        if not foreign_ok:
            statuses[host]="SKIP_FOREIGN_UNVERIFIED"
            continue
        if not russian_error:
            statuses[host]="SKIP_RU_TCP_TLS_ERROR_NOT_REPRODUCED"
            continue
        try:
            ip=renderer.validated_public_ip(a["origin_ipv4"])
            cc=renderer.core_add(core,host)
            nn=renderer.nginx_add(nginx,host,ip)
            if cc==core or nn==nginx:raise RuntimeError("NON_ADDITIVE")
        except (ValueError,RuntimeError,AssertionError) as exc:
            statuses[host]="SKIP_OVERLAP_"+type(exc).__name__
            continue
        selected.append((host,ip))
        core,nginx=cc,nn
        statuses[host]="VERIFIED_ELIGIBLE"
    info={
        "eligible":len(selected),
        "selected_from_first100":len(selected),
        "no_live_mutations":True,
        "first100_sha256":sha("\n".join(HOSTS)+"\n"),
        "checked_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_sha256":{"core":sha(start_core),"nginx":sha(start_nginx)},
        "target_sha256":{"core":sha(core),"nginx":sha(nginx)},
        "decisions":dict(collections.Counter(statuses.values()))
    }
    (OUT/"summary.json").write_text(json.dumps(info,indent=2,sort_keys=True)+"\n")
    (OUT/"tcp13-decisions.json").write_text(json.dumps(statuses,indent=2,sort_keys=True)+"\n")
    (OUT/"eligible-manifest.tsv").write_text("".join(h+"\t"+ip+"\n" for h,ip in selected))
    first.emit("RU_TCP_FOLLOWUP_PREFLIGHT",count=len(selected),decisions=info["decisions"],hosts=[h for h,_ in selected])
    return selected,info

def self_test():
    if len(HOSTS)!=13 or len(set(HOSTS))!=13:raise RuntimeError("FIXED_SCOPE_BAD")
    for h in HOSTS:renderer.validate_domain(h)
    assert renderer.DNS_INGRESS==owner.RU and owner.RU!=owner.EDGE
    print("TCP13_REUSE_OFFLINE=PASS",flush=True)

if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("self-test","deploy"):
        raise SystemExit("usage: script self-test|deploy")
    if sys.argv[1]=="self-test":
        self_test()
    else:
        first.safe_plan=plan_ru_errors
        first.deploy()
