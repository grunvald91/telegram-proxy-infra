#!/usr/bin/env python3
"""Synchronize owner DNS request status with independently verified shared routes.

Only after live DoT and end-to-end TLS pass for ALL 12 owner-approved
Antigravity hosts and the bot's COVERED migration has been applied.
Never mutates CoreDNS, Nginx, existing route ownership or other products.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
root=Path(__file__).resolve().parent

def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,root/filename)
    if not spec or not spec.loader:raise RuntimeError("Missing trusted source")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

verified=load("antigravity_verify","mnebydns-antigravity-live-readonly-20261110.py")
batch=verified.batch
owner=batch.owner
domains=batch.DOMAINS
shared=domains[1:]
assert len(domains)==12 and len(set(domains))==12
assert domains[0]=="antigravity.google"

def safe_names(names):
    return ",".join("'"+owner._render.validate_domain(n)+"'" for n in names)

def read_rows():
    raw=owner.sql(
        "SELECT domain||'|'||product||'|'||status FROM dns_admin_domains"
        " WHERE domain IN ("+safe_names(domains)+") ORDER BY domain"
    )
    records={}
    for item in raw.splitlines():
        parts=item.split("|")
        if len(parts)!=3:raise RuntimeError("Invalid DB row")
        domain,product,status=parts
        if domain in records or domain not in domains:raise RuntimeError("Unexpected DB record")
        records[domain]=(product,status)
    if len(records)!=12:raise RuntimeError("Canonical Antigravity DB rows missing")
    return records

def main():
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Live DNS or nginx differs from trusted checkpoint")
    # Read-only live probe terminates before any write if one hostname fails.
    verified.main()
    version=owner.sql(
        "SELECT count(*) FROM deployment_schema_migrations"
        " WHERE file_name='0110_dns_admin_existing_route_coverage.sql'"
    ).strip()
    if version!="1":
        raise RuntimeError("COVERED migration not yet applied; no database changes")
    before=read_rows()
    if before["antigravity.google"][1]!="ACTIVE":
        raise RuntimeError("Main Antigravity exact-host route must remain ACTIVE")
    for domain in shared:
        product,status=before[domain]
        if product!="Antigravity" or status not in ("FAILED","PENDING","COVERED"):
            raise RuntimeError("Unexpected existing route ownership or status: "+domain)
    affected=owner.sql(
        "UPDATE dns_admin_domains SET status='COVERED',"
        " last_error_code=NULL,updated_at=now()"
        " WHERE domain IN ("+safe_names(shared)+")"
        " AND product='Antigravity' AND status IN ('FAILED','PENDING')"
        " RETURNING domain"
    )
    updated=[s.strip() for s in affected.splitlines() if s.strip()]
    if any(d not in shared for d in updated):
        raise RuntimeError("Changed unexpected domain!")
    after=read_rows()
    if any(after[domain]!=("Antigravity","COVERED") for domain in shared):
        raise RuntimeError("COVERED status not recorded for all 11 shared routes")
    if after["antigravity.google"][1]!="ACTIVE":
        raise RuntimeError("Existing exact-host activation unexpectedly changed")
    print("antigravity_verified_existing_routes_COVERED=11",flush=True)
    print("antigravity_exact_host_ACTIVE=1",flush=True)
    print("antigravity_status_rows_updated="+str(len(updated)),flush=True)
    print("antigravity_dns_nginx_changed=false",flush=True)

if __name__=="__main__":main()
