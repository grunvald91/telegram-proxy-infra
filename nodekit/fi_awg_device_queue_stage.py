#!/usr/bin/env python3
"""Install exactly pinned FI217 device-request queue migration 0136 on RU188.

One schema-only transaction. No live VPN peer, flag, service or subscriber
changes. Requires already disabled RU188 AWG delivery unit, canonical
loopback-only PostgreSQL and independently verified node/controller keys.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

import fi_awg_delivery_db_stage as trust

COMMIT="80abe4e7adc26f452d06974f6b5eb0bcbe46c922"
BLOB="0d68a5cd47c18b3f55c207a8209f741f20ce6f3b"
STAGE=re.compile(r"/run/fi-awg-device-queue\.[A-Za-z0-9]{8}\Z")
FILENAME="0136_awg_device_enrollment_queue.sql"


def checked_stage(directory:Path) -> bytes:
    if not STAGE.fullmatch(str(directory)):
        trust.stop("fi_device_queue_unapproved_stage")
    trust.trusted_parent(directory)
    source=trust.private_file(directory/FILENAME,10000)
    actual=hashlib.sha1(
        b"blob "+str(len(source)).encode("ascii")+b"\0"+source).hexdigest()
    if actual != BLOB or not source.startswith(
       b"-- FI217 AWG native device enrollment"):
        trust.stop("fi_device_queue_independent_source_pin_mismatch")
    return source


def check_security() -> None:
    trust.preflight()
    flag=trust.sql(
        "SELECT enabled::text FROM public.vpn_release_flags "
        "WHERE feature='vpn_awg_clients';")
    if flag!="false":
        trust.stop("fi_device_queue_release_must_remain_off")
    if not trust.role_exists():
        trust.stop("fi_device_queue_worker_role_missing")
    found=trust.sql(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mnebyvpn_site_auth')::text;")
    if found!="true":
        trust.stop("fi_device_queue_site_auth_role_missing")


def verify_installed() -> None:
    if trust.sql("SELECT to_regclass('public.vpn_awg_device_requests')::text;") != \
       "vpn_awg_device_requests":
        trust.stop("fi_device_queue_table_not_installed")
    roles=trust.sql("""
SELECT has_table_privilege('mnebyvpn_awg_delivery',
                          'public.vpn_awg_device_requests','SELECT')::text,
       has_table_privilege('mnebyvpn_awg_delivery',
                          'public.vpn_awg_device_requests','UPDATE')::text,
       has_table_privilege('mnebyvpn_awg_delivery',
                          'public.vpn_awg_device_requests','INSERT')::text,
       has_table_privilege('mnebyvpn_awg_delivery',
                          'public.vpn_awg_device_requests','DELETE')::text,
       has_table_privilege('mnebyvpn_site_auth',
                          'public.vpn_awg_device_requests','SELECT')::text,
       has_table_privilege('mnebyvpn_site_auth',
                          'public.vpn_awg_device_requests','INSERT')::text,
       has_table_privilege('mnebyvpn_site_auth',
                          'public.vpn_awg_device_requests','UPDATE')::text,
       has_function_privilege('mnebyvpn_site_auth',
                 'public.website_request_fi_awg_device(text,uuid,text)',
                 'EXECUTE')::text,
       has_function_privilege('mnebyvpn_site_auth',
                 'public.website_fi_awg_device_status(text,uuid,text)',
                 'EXECUTE')::text;
""")
    if roles!="true|true|false|false|false|false|false|true|true":
        trust.stop("fi_device_queue_unapproved_role_permissions")
    # No customer requests may pre-exist on a first install. Idempotent
    # re-run on a later offline host is permitted, but NEVER delete rows.
    tables=trust.sql("""
SELECT COUNT(*)::text FROM pg_attribute
 WHERE attrelid='public.vpn_awg_device_requests'::regclass
 AND attname IN ('entitlement_id','node_id','peer_public_key',
 'billing_revision','state','attempts','claimed_at','next_attempt_at')
 AND NOT attisdropped;
""")
    if tables!="8":
        trust.stop("fi_device_queue_schema_contract_mismatch")
    if trust.sql(
       "SELECT enabled::text FROM public.vpn_release_flags "
       "WHERE feature='vpn_awg_clients';")!="false":
        trust.stop("fi_device_queue_release_changed")


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--stage",type=Path,required=True)
    args=parser.parse_args()
    checked=checked_stage(args.stage)
    check_security()
    existing=trust.sql(
        "SELECT to_regclass('public.vpn_awg_device_requests')::text;")
    if not existing:
        # Executes exactly the reviewed, source-pinned SQL. All DDL/DCL is
        # atomic in BEGIN/COMMIT, and the worker remains stopped.
        trust.sql(checked.decode("utf-8"))
        action="INSTALLED"
    elif existing=="vpn_awg_device_requests":
        action="ALREADY_PRESENT"
    else:
        trust.stop("fi_device_queue_unapproved_existing_schema")
    verify_installed()
    trust.verify_privileges()
    trust.preflight()
    print("FI_AWG_DEVICE_QUEUE="+action+";SITE_ROLE=RPC_ONLY;"
          "WORKER_ROLE=SCOPED;WORKER_ACTIVE=false;"
          "CUSTOMER_RELEASE=false;REAL_PEERS_MODIFIED=false")


if __name__=="__main__":
    try:
        main()
    except (trust.StageError,OSError,ValueError,TypeError,KeyError,UnicodeError):
        raise SystemExit(2)
