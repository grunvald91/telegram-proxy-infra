#!/usr/bin/env python3
"""Owner-approved unattended permanent rollout for SIX study-listed Microsoft hosts.

Uses the SAME owner exact-host CoreDNS + Nginx SNI routing and verified origin
machinery as the live Gemini/Claude routes. Never configures wildcard rules.
Every host is staged with an independent 60-minute rollback timer, then
server-side TLS/DoT verification and checkpoint promotion. No phone check.
Failed hosts remain FAILED and do not block another independently safe host.
An unverified rollback or shared-checkpoint drift aborts the entire batch.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
import re
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent
CONTROLLER=ROOT/"mnebydns-owner-domain-controller-20261110.py"
SPEC=importlib.util.spec_from_file_location("owner_domain_controller",CONTROLLER)
if SPEC is None or SPEC.loader is None:raise RuntimeError("Controller not available")
owner=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owner)

# Only study-named exact FQDNs, NOT all domains under microsoft.com.
TARGETS=(
    "copilot.microsoft.com",
    "software-static.download.prss.microsoft.com",
    "xboxdesignlab.xbox.com",
    "xbox.com",
    "bing.com",
    "microsoft.com",
)
ACTIVE_TRANSITIONS=(
    "APPLY_REQUESTED","PROBING","CANARY",
    "CONFIRM_REQUESTED","CONFIRMING","ROLLBACK_REQUESTED",
    "REMOVAL_PENDING","REMOVING",
)
IDENTIFIER=re.compile(r"[1-9][0-9]{0,14}$")

def row(domain):
    if domain not in TARGETS:raise ValueError("Unexpected hostname")
    query=(
        "SELECT id||'|'||domain||'|'||status||'|'||revision||'|'||"
        "coalesce(canary_run_id::text,'')||'|'||"
        "coalesce(extract(epoch from canary_expires_at)::bigint::text,'')||'|'||"
        "coalesce(last_error_code,'')||'|'||product"
        " FROM dns_admin_domains WHERE domain='"+domain+"'"
    )
    output=owner.sql(query).strip()
    parts=output.split("|")
    if len(parts)!=8:raise RuntimeError("Microsoft row absent or malformed")
    keys=("id","domain","status","revision","run","expires","error","product")
    item=dict(zip(keys,parts))
    if item["domain"]!=domain or not IDENTIFIER.fullmatch(item["id"]) or not IDENTIFIER.fullmatch(item["revision"]):
        raise RuntimeError("Unexpected database record identity")
    if item["run"] and not re.fullmatch(r"[1-9][0-9]{8,12}",item["run"]):
        raise RuntimeError("Unsafe historical canary id")
    if item["expires"] and not item["expires"].isdigit():
        raise RuntimeError("Bad canary expiration")
    return item

def cas(domain,source,destination,actor_run=None,require_fresh=False):
    item=row(domain)
    if item["status"]!=source:return False
    expiry=(" AND canary_expires_at>now()+interval '6 minutes'"
            if require_fresh else "")
    # Never overwrite any other domain or already changed revision.
    q=(
      "UPDATE dns_admin_domains SET status='"+destination+"',"
      "revision=revision+1,updated_at=now()"
      +((",last_error_code=NULL,product='Microsoft'") if destination=="APPLY_REQUESTED" else "")
      +" WHERE id="+item["id"]+" AND revision="+item["revision"]+
      " AND domain='"+domain+"' AND status='"+source+"'"+expiry+
      " RETURNING id"
    )
    return owner.sql(q).strip()==item["id"]

def other_owner_transition(name):
    result=owner.sql(
      "SELECT count(*) FROM dns_admin_domains WHERE domain<>'"+name+"'"
      " AND status IN ("+",".join("'"+x+"'" for x in ACTIVE_TRANSITIONS)+")"
    )
    return int(result.strip())

def health(domain):
    # These strictly verify public DoT result, both alternate RR types,
    # five stable Gemini/Claude/Grok/X/TikTok controls, and RU->DE TLS.
    owner.oracle_canary_check(domain,True)
    owner.tls_public_route(domain)

def rollback_live_canary(name):
    current=row(name)
    if current["status"]!="CANARY":return
    if not cas(name,"CANARY","ROLLBACK_REQUESTED"):
        raise RuntimeError("Unable to request rollback")
    current=row(name)
    owner.cancel_canary(current,expired=False)
    if row(name)["status"]!="CANCELLED":
        raise RuntimeError("Canary rollback status not committed")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Rollback changed or failed stable baseline")

def commit_canary(name):
    current=row(name)
    if current["status"]!="CANARY":
        raise RuntimeError("Cannot commit without verified CANARY")
    # Actual live route must already have a trusted CA TLS connection from RU.
    health(name)
    if not cas(name,"CANARY","CONFIRM_REQUESTED",require_fresh=True):
        raise RuntimeError("Canary cannot be committed with at least 6 minutes remaining")
    current=row(name)
    if current["status"]!="CONFIRM_REQUESTED":
        raise RuntimeError("Confirmation not persisted")
    owner.confirm(current)
    committed=row(name)
    if committed["status"]!="ACTIVE":
        raise RuntimeError("Checkpoint not ACTIVE after confirmation")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Stable checkpoint mismatch after confirmation")
    health(name)
    print("microsoft_permanent_ACTIVE="+name,flush=True)

def prepare(name):
    current=row(name)
    print("microsoft_before="+name+":"+current["status"]+":"+current["error"],flush=True)
    if current["status"]=="ACTIVE":
        health(name)
        print("microsoft_already_verified_ACTIVE="+name,flush=True)
        return "ACTIVE"
    if current["status"]=="COVERED":
        # Existing shared route is owned elsewhere. Never change it.
        health(name)
        print("microsoft_existing_COVERED="+name,flush=True)
        return "COVERED"

    if other_owner_transition(name):
        print("microsoft_blocked_by_other_owner_transition="+name,flush=True)
        return "DEFERRED"

    if current["status"]=="CANARY":
        now=int(time.time())
        # Confirm existing canary if it remains safely distant from expiry.
        if int(current["expires"] or 0)>now+7*60:
            commit_canary(name)
            return "ACTIVE"
        rollback_live_canary(name)
        current=row(name)

    if current["status"] not in ("PENDING","FAILED","CANCELLED"):
        print("microsoft_unexpected_workflow_state="+name+":"+current["status"],flush=True)
        return "DEFERRED"
    if not owner.live_checkpoint_unchanged():
        print("microsoft_unverified_checkpoint="+name,flush=True)
        return "DEFERRED"
    if not cas(name,current["status"],"APPLY_REQUESTED"):
        raise RuntimeError("Microsoft request CAS lost")
    return "REQUESTED"

def self_test():
    assert len(TARGETS)==6 and len(set(TARGETS))==6
    assert TARGETS[0]=="copilot.microsoft.com"
    assert TARGETS[-1]=="microsoft.com"
    assert "google.com" not in TARGETS
    for host in TARGETS:
        owner._render.validate_domain(host)
    assert len(set(ACTIVE_TRANSITIONS))==len(ACTIVE_TRANSITIONS)
    assert CONTROLLER.is_file()
    print("microsoft_six_offline_contract=PASS",flush=True)

def main():
    if len(sys.argv)==2 and sys.argv[1]=="self-test":
        self_test();return
    if len(sys.argv)!=2 or sys.argv[1]!="run":
        raise SystemExit("Usage: self-test | run")
    self_test()
    runid=os.environ.get("GITHUB_RUN_ID","")
    if not re.fullmatch(r"[1-9][0-9]{8,11}",runid):
        raise RuntimeError("Invalid GitHub run ID")
    failed=[]
    statuses=[]
    for index,name in enumerate(TARGETS,1):
        # Each independently staged canary has a distinct systemd rollback timer.
        owner.RUNID=runid+str(index)
        owner.WORK="/tmp/mnebydns-owner-domain-"+owner.RUNID
        print("microsoft_start="+name,flush=True)
        try:
            state=prepare(name)
            if state in ("ACTIVE","COVERED"):
                statuses.append((name,state));continue
            if state!="REQUESTED":
                failed.append(name+"|"+state)
                continue
            item=row(name)
            assert item["status"]=="APPLY_REQUESTED"
            owner.apply(item)
            current=row(name)
            if current["status"]!="CANARY":
                print("microsoft_canary_NOT_ESTABLISHED="+name+":"+current["status"],flush=True)
                failed.append(name+"|"+current["status"])
                continue
            if current["run"]!=owner.RUNID:
                raise RuntimeError("Mismatch between staged and committed canary identifier")
            commit_canary(name)
            statuses.append((name,"ACTIVE"))
        except Exception as exc:
            print("microsoft_route_error="+name+":"+type(exc).__name__+
                  ":"+str(exc)[:200].replace("\n"," "),flush=True)
            try:
                latest=row(name)
                if latest["status"]=="CANARY":
                    rollback_live_canary(name)
                if not owner.live_checkpoint_unchanged():
                    raise RuntimeError("STOP_SHARED_CHECKPOINT_NOT_VERIFIED")
            except Exception:
                print("microsoft_CRITICAL_ROLLBACK_NOT_VERIFIED="+name,flush=True)
                raise
            failed.append(name+"|"+row(name)["status"])
    print("microsoft_results_begin",flush=True)
    for name in TARGETS:
        status=row(name)["status"]
        print(name+"|"+status,flush=True)
    print("microsoft_results_end",flush=True)
    print("microsoft_success_count="+str(len(statuses)),flush=True)
    print("microsoft_incomplete_count="+str(len(failed)),flush=True)
    if failed:
        raise RuntimeError("MICROSOFT_BATCH_INCOMPLETE: "+", ".join(failed))
    print("microsoft_permanent_six_verified=true",flush=True)

if __name__=="__main__":
    main()
