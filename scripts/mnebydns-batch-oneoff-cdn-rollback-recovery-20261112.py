#!/usr/bin/env python3
"""Single incident-specific, compare-and-swap recovery after verified rollback.

Never clears a general incident. This only re-queues the exact 2026-11-12
3dwarehouse canary whose route was demonstrably restored and whose failure
was a verified PostgreSQL INET /32 parsing mismatch. No arbitrary hostnames or run IDs accepted.
"""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import re
import shlex
import sys

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location(
    "oneoff_owner",ROOT/"mnebydns-owner-domain-controller-20261110.py")
if spec is None or spec.loader is None:
    raise RuntimeError("Missing owner controller")
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
HOST="3dwarehouse.sketchup.com"
OLD_RUN_ID="432181801921"
PRODUCT="Research 2026-11"
REASON="BATCH_INCIDENT_CANARY_ABORT"

def check():
    assert owner._render.validate_domain(HOST)==HOST
    assert re.fullmatch(r"[1-9][0-9]{8,12}",OLD_RUN_ID)
    assert PRODUCT=="Research 2026-11"
    print("ONEOFF_CDN_RECOVERY_OFFLINE=PASS")

def actual():
    if os.environ.get("GITHUB_REF")!="refs/heads/main" or \
       os.environ.get("GITHUB_EVENT_NAME")!="push":
        raise RuntimeError("One-off reset only on reviewed main push")
    if not owner.PINNED_SSH_HOSTS.is_file():
        raise RuntimeError("Missing pinned SSH host keys")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Cannot touch DB after checkpoint drift")
    busy=owner.sql("SELECT count(*) FROM dns_admin_domains WHERE status IN "
        "('APPLY_REQUESTED','PROBING','CANARY','CONFIRM_REQUESTED','CONFIRMING',"
        "'ROLLBACK_REQUESTED','REMOVAL_PENDING','REMOVING')").strip()
    if busy!="0":
        raise RuntimeError("Another canary or owner transition exists")
    # Fail-safe: known failed experiment is absent from live DNS and Nginx.
    marker=owner._render.mark(HOST)
    probe=(
      "set -Eeuo pipefail; "
      "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
      "[[ \"$root\" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]; "
      "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null); "
      "cmp -s \"$root/dns.stable\" /opt/mnebydns-dot/Corefile; "
      "cmp -s \"$root/nginx.stable\" /etc/nginx/nginx.conf; "
      "! grep -Fq -- "+shlex.quote(marker)+" /opt/mnebydns-dot/Corefile; "
      "! grep -Fq -- "+shlex.quote(marker)+" /etc/nginx/nginx.conf; "
      "nginx -t >/dev/null 2>&1; "
      "systemctl is-active --quiet nginx; "
      "systemctl is-active --quiet mnebydns-dot.service; "
      "echo FIRST_CANARY_ABSENT_AND_BASELINE_RESTORED"
    )
    result=owner.ssh("de","bash -c "+shlex.quote(probe),50).strip()
    if result!="FIRST_CANARY_ABSENT_AND_BASELINE_RESTORED":
        raise RuntimeError("Cannot prove last canary was removed")
    owner.oracle_canary_check(HOST,False)
    state=owner.sql("SELECT status||'|'||coalesce(last_error_code,'')||'|'||"
        "coalesce(canary_run_id::text,'')||'|'||product "
        "FROM dns_admin_domains WHERE domain='"+HOST+"'").strip()
    wanted="FAILED|"+REASON+"|"+OLD_RUN_ID+"|"+PRODUCT
    if state!=wanted:
        raise RuntimeError("One-off recovery row not an exact match; observed "+state)
    changed=owner.sql(
        "UPDATE dns_admin_domains SET status='PENDING',revision=revision+1,"
        "last_error_code=NULL,canary_run_id=NULL,canary_expires_at=NULL,"
        "verified_origin_ip=NULL,updated_at=now() WHERE domain='"+HOST+"'"
        " AND product='"+PRODUCT+"' AND status='FAILED'"
        " AND last_error_code='"+REASON+"'"
        " AND canary_run_id="+OLD_RUN_ID+" RETURNING domain").strip()
    if changed!=HOST:
        raise RuntimeError("Single-use recovery compare-and-swap failed")
    print("ONEOFF_CDN_CANARY_RESET_TO_PENDING="+HOST,flush=True)
    print("ONEOFF_LIVE_CONFIGS_UNCHANGED=true",flush=True)

if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("self-test","recover"):
        raise SystemExit("usage: self-test|recover")
    if sys.argv[1]=="self-test":
        check()
    else:
        actual()
