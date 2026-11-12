#!/usr/bin/env python3
"""Read-only, source-attested inventory of 108 SmartDNS RU403/451 candidates.

Uses the established pinned SSH and canonical RU PostgreSQL SELECT only;
does not modify owner-domain states, nginx, CoreDNS, checkpoints, or timers.
"""
from __future__ import annotations
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re
import shlex

ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/"scripts/mnebydns-batch-108-canary-20261112.py"
OUT=ROOT/"mnebydns-108-live-status"
spec=importlib.util.spec_from_file_location("mnebydns_batch_for_status",SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("Missing tested 108-domain batch controller")
batch=importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
owner=batch.owner
STATES=("PENDING","FAILED","ACTIVE","APPLY_REQUESTED","PROBING","CANARY",
        "CONFIRM_REQUESTED","CONFIRMING","ROLLBACK_REQUESTED",
        "REMOVAL_PENDING","REMOVING","CANCELLED")

def checked_rows(raw):
    data={}
    for line in raw.splitlines():
        fields=line.split("|")
        if len(fields)!=5:
            raise RuntimeError("Malformed RU PostgreSQL 108-domain SELECT result")
        name,state,product,error,ip=fields
        name=owner._render.validate_domain(name)
        if name in data or state not in STATES or any(len(v)>200 for v in fields):
            raise RuntimeError("Duplicate/unknown/oversized live state")
        data[name]={"status":state,"product":product,"error":error,"ip":ip}
    return data

def summarize(names,rows):
    if len(names)!=108 or len(set(names))!=108:
        raise RuntimeError("108 inventory changed")
    counters=collections.Counter()
    failures=[]
    active=[]
    abnormal=[]
    for host in names:
        if host not in rows:
            abnormal.append({"domain":host,"reason":"NO_DB_RECORD"})
            continue
        entry=rows[host]
        status=entry["status"]
        counters[status]+=1
        if entry["product"]!=batch.PRODUCT:
            if status!="ACTIVE":
                abnormal.append({"domain":host,"reason":"FOREIGN_OWNER_NON_ACTIVE",
                                 "status":status})
        if status=="FAILED":
            failures.append({"domain":host,"reason":entry["error"]})
        if status=="ACTIVE":
            active.append(host)
    circuit=[r for r in failures if r["reason"].startswith("BATCH_INCIDENT_")]
    busy=[h for h in names if rows.get(h,{}).get("status") in batch.BUSY]
    return {"candidate_total":len(names),"status_counts":dict(sorted(counters.items())),
            "missing_or_abnormal":abnormal,"active":active,"failed":failures,
            "incident_circuit_breaker":circuit,"busy_candidates":busy}

def inspect_active_routes(names,rows,core,nginx):
    items=[]
    for host in names:
        entry=rows.get(host)
        if not entry or entry["status"]!="ACTIVE":
            continue
        marker=owner._render.mark(host)
        item={"domain":host,
              "core_marker":marker in core,
              "nginx_marker":marker in nginx,
              "product":entry["product"]}
        # A foreign ACTIVE route may legitimately use a different mechanism.
        if entry["product"]==batch.PRODUCT:
            if not item["core_marker"] or not item["nginx_marker"]:
                item["health"]="RESEARCH_ACTIVE_MARKER_MISSING"
            else:
                try:
                    ip=owner.pg_inet_host(entry["ip"])
                    item["health"]=("PIN_PRESENT" if
                        re.search(r"(?m)^\s*"+re.escape(host)+r"\s+"+
                                  re.escape(ip)+r":443;",nginx)
                        else "ACTIVE_PINNED_IP_MISSING")
                except (ValueError,RuntimeError):
                    item["health"]="UNVERIFIED_ORIGIN_METADATA"
        else:
            item["health"]="FOREIGN_ACTIVE_NOT_MODIFIED"
        items.append(item)
    return items

def self_test():
    names=batch.inventory()
    fake={n:{"status":"PENDING","product":batch.PRODUCT,"error":"","ip":""}
          for n in names}
    fake[names[0]]["status"]="ACTIVE"
    fake[names[1]]["status"]="FAILED"
    fake[names[1]]["error"]="BATCH_CANDIDATE_HTTPS_FAILED"
    result=summarize(names,fake)
    assert result["status_counts"]=={"ACTIVE":1,"FAILED":1,"PENDING":106}
    assert result["incident_circuit_breaker"]==[]
    fake[names[1]]["error"]="BATCH_INCIDENT_CANARY_ABORT"
    assert len(summarize(names,fake)["incident_circuit_breaker"])==1
    assert checked_rows("a.example.com|ACTIVE|Research 2026-11||1.1.1.1/32\n")[
        "a.example.com"]["ip"]=="1.1.1.1/32"
    print("MNEBYDNS_108_LIVE_STATUS_OFFLINE=PASS")

def inspect():
    names=batch.inventory()
    # SQL is static; neither DB mutators nor owner health functions are called.
    query=("SELECT domain||'|'||status||'|'||coalesce(product,'')||'|'||"
           "coalesce(last_error_code,'')||'|'||"
           "coalesce(verified_origin_ip::text,'') FROM dns_admin_domains ORDER BY domain")
    raw=owner.sql(query)
    rows=checked_rows(raw)
    info=summarize(names,rows)
    info["auto_enabled"]=batch.enabled()
    info["global_pending_owner_operations"]={
        key:sum(r["status"]==key for r in rows.values()) for key in batch.BUSY
    }
    info["baseline_clean"]=owner.live_checkpoint_unchanged()
    if not info["baseline_clean"]:
        raise RuntimeError("DE stable checkpoint drift or read-only verification failed")
    # Actual live state only; never output raw nginx/CoreDNS config.
    check=("set -Eeuo pipefail; "
           "systemctl is-active --quiet nginx; "
           "systemctl is-active --quiet mnebydns-dot.service; "
           "systemctl is-active --quiet mnebydns-googlepilot.service; "
           "systemctl is-active --quiet xray.service; "
           "nginx -t >/dev/null 2>&1; echo SERVICES_HEALTHY")
    info["services_healthy"]=(owner.ssh("de","bash -c "+shlex.quote(check),40).strip()
                             =="SERVICES_HEALTHY")
    if not info["services_healthy"]:
        raise RuntimeError("DE service health is not confirmed")
    core=owner.ssh("de","cat /opt/mnebydns-dot/Corefile",40)
    nginx=owner.ssh("de","cat /etc/nginx/nginx.conf",40)
    info["active_route_checks"]=inspect_active_routes(names,rows,core,nginx)
    info["active_route_issues"]=[v for v in info["active_route_checks"]
       if v["health"] not in ("PIN_PRESENT","FOREIGN_ACTIVE_NOT_MODIFIED")]
    info["remaining_pending"]=info["status_counts"].get("PENDING",0)
    info["next_pending"]=next((n for n in names if
        rows.get(n,{}).get("status")=="PENDING"),None)
    info["ready_for_next_guarded_wave"]=(
        info["baseline_clean"] and info["services_healthy"]
        and not info["active_route_issues"]
        and not info["incident_circuit_breaker"]
        and not info["missing_or_abnormal"]
        and not any(info["global_pending_owner_operations"].values())
    )
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"live-status.json").write_text(
        json.dumps(info,indent=2,ensure_ascii=False,sort_keys=True)+"\n")
    lines=["# MNEBYDNS 108-domain live status, read-only","",
           "Validated current DE stable checkpoint and RU PostgreSQL database.",
           "",
           "- Total reviewed: "+str(info["candidate_total"]),
           "- Pending: "+str(info["remaining_pending"]),
           "- Active: "+str(info["status_counts"].get("ACTIVE",0)),
           "- Failed: "+str(info["status_counts"].get("FAILED",0)),
           "- Next: "+str(info["next_pending"]),
           "- Ready for a guarded wave: "+str(info["ready_for_next_guarded_wave"]),
           "- Unresolved circuit breakers: "+str(len(info["incident_circuit_breaker"])),
           "- Existing ACTIVE route issues: "+str(len(info["active_route_issues"])),
           "",
           "## Statuses",
           ""]
    for key,value in info["status_counts"].items():
        lines.append("- "+key+": "+str(value))
    lines.extend(["","## Active domains",""])
    for entry in info["active_route_checks"]:
        lines.append("- "+entry["domain"]+": "+entry["health"])
    lines.extend(["","## Failed domains",""])
    for entry in info["failed"]:
        lines.append("- "+entry["domain"]+": "+entry["reason"])
    (OUT/"report.md").write_text("\n".join(lines)+"\n")
    print("MNEBYDNS_LIVE_STATUS_108="+json.dumps({
        k:info[k] for k in ("status_counts","remaining_pending","next_pending",
        "auto_enabled","ready_for_next_guarded_wave")},ensure_ascii=False),flush=True)
    print("MNEBYDNS_LIVE_STATUS_ACTIVE="+",".join(info["active"]),flush=True)
    print("MNEBYDNS_LIVE_STATUS_FAILED="+json.dumps(info["failed"],ensure_ascii=False),flush=True)
    print("MNEBYDNS_LIVE_CONFIG_CHANGED=false",flush=True)
    if not info["ready_for_next_guarded_wave"]:
        print("MNEBYDNS_LIVE_NEXT_WAVE_BLOCKED=true",flush=True)

if __name__=="__main__":
    args=argparse.ArgumentParser()
    args.add_argument("mode",choices=("self-test","inspect"))
    parsed=args.parse_args()
    if parsed.mode=="self-test":self_test()
    else:inspect()
