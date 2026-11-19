#!/usr/bin/env python3
"""Safely register the EXISTING FI217 AWG node pool as STAGED, never VERIFIED.

FI mode: read pinned staged AWG source and emit only public server key material.
RU mode: verify root identity, FI enrollment and unpublished release, insert
exactly one staged FI pool row transactionally into existing PostgreSQL.
Never activates AWG, releases clients, or fabricates fresh external E2E proof.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import fi_awg_signed_canary as canary

FI_POOL = {
    "node_id": "fi-test-01",
    "endpoint_host": "fi.mnebyvpn.site",
    "subnet_cidr": "10.73.91.0/24",
    "listen_port": 51821,
    "state": "staged",
}
DB_CONTAINER = "mnebyvpn-stage-postgres"


def fail(code: str) -> None:
    print("FI_AWG_POOL_STAGE_BLOCKED="+code, file=sys.stderr)
    raise ValueError(code)


def valid_key(value: str) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode() == value
    except (ValueError, base64.binascii.Error):
        return False


def read_input(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        fail("unsafe_pool_payload")
    meta = path.stat()
    if (meta.st_uid != 0 or meta.st_mode & 0o077 or
            not 40 <= meta.st_size <= 1024):
        fail("unsafe_pool_payload")
    try:
        payload = json.loads(path.read_bytes())
    except (UnicodeDecodeError, TypeError, ValueError):
        fail("invalid_pool_json")
    if (not isinstance(payload, dict) or
            set(payload) != set(FI_POOL) | {"server_public_key"} or
            any(payload.get(k) != v for k, v in FI_POOL.items()) or
            not valid_key(payload.get("server_public_key"))):
        fail("unapproved_pool_identity")
    return payload


def export_fi() -> None:
    if not canary.is_host(canary.FI_IP):
        fail("not_existing_fi217")
    from awg_lifecycle import validate
    node = canary.FI_NODE
    canary.pinned_spki(node / "identity/node-public.spki", canary.NODE_SHA)
    canary.pinned_spki(node / "controller-access.spki", canary.CONTROLLER_SHA)
    manifest = json.loads(canary.protected(node / "manifest.json", 10000))
    if (manifest.get("node_id") != canary.NODE_ID or
            manifest.get("advertise_host") != canary.HOST or
            manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            manifest.get("activation_enabled") is not False):
        fail("fi_manifest_not_unpublished")
    checked = validate(node)
    if (checked.get("zero_peers") is not True or
            checked.get("source_verified") is not True):
        fail("fi_awg_binary_or_baseline_not_verified")
    candidate = json.loads(canary.protected(node / "amneziawg/manifest.json", 15000))
    key = candidate.get("server_public_key")
    if not valid_key(key):
        fail("fi_server_public_key_invalid")
    for unit in ("mnebyvpn-nodekit-awg@fi-test-01.service",
                 "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service"):
        check = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            capture_output=True, timeout=8, check=False)
        if check.returncode == 0:
            fail("fi_awg_service_active")
    print(json.dumps(dict(FI_POOL, server_public_key=key),
                     sort_keys=True, separators=(",", ":")))


def stage_ru(path: Path) -> None:
    # RU188 only. The existing controller's signed runtime, root identity
    # and NO-CLIENTS gates are checked before the first database mutation.
    import fi_awg_worker_source_stage as trust
    trust.require_safe_dormant()
    payload = read_input(path)
    key = payload["server_public_key"]
    # Only the exact canonical reviewed FI row is created. A changed key,
    # address, subnet, node state or any existing proof is NEVER overwritten.
    sql = f"""
BEGIN;
DO $check$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.vpn_node_enrollment_inventory
                WHERE node_id='fi-test-01' AND status='enrolled'
                  AND endpoint_host='fi.mnebyvpn.site') THEN
    RAISE EXCEPTION 'FI node not enrolled';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM public.vpn_release_flags
                WHERE feature='vpn_awg_clients' AND enabled=false) THEN
    RAISE EXCEPTION 'AWG client release not disabled';
  END IF;
END $check$;
INSERT INTO public.vpn_awg_node_pools
 (node_id,endpoint_host,server_public_key,listen_port,subnet_cidr,
  state,external_e2e_proof_sha256,verified_at)
VALUES ('fi-test-01','fi.mnebyvpn.site','{key}',51821,
        '10.73.91.0/24','staged',NULL,NULL)
ON CONFLICT(node_id) DO NOTHING;
DO $check$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM public.vpn_awg_node_pools
      WHERE node_id='fi-test-01' AND endpoint_host='fi.mnebyvpn.site'
      AND server_public_key='{key}' AND listen_port=51821
      AND subnet_cidr='10.73.91.0/24'::cidr
      AND state='staged' AND external_e2e_proof_sha256 IS NULL
      AND verified_at IS NULL) THEN
    RAISE EXCEPTION 'unexpected existing FI pool or drift';
  END IF;
END $check$;
COMMIT;
"""
    result = subprocess.run(
        ["docker", "exec", "-i", DB_CONTAINER, "psql",
         "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
         "-U", "mnebyvpn_stage", "-d", "mnebyvpn_stage"],
        input=sql, text=True, capture_output=True,
        timeout=16, check=False)
    if result.returncode:
        fail("fi_pool_transaction_refused")
    print("FI_AWG_NODE_POOL=STAGED;PRODUCTION_E2E_VERIFIED=false;"
          "AWG_WORKER_STARTED=false;CUSTOMER_RELEASE=false")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("export-fi", "stage-ru"), required=True)
    parser.add_argument("--material", type=Path)
    args = parser.parse_args()
    if args.mode == "export-fi":
        if args.material is not None:
            fail("unexpected_fi_material")
        export_fi()
    else:
        if args.material is None:
            fail("missing_ru_material")
        stage_ru(args.material)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, RuntimeError, KeyError,
            subprocess.TimeoutExpired, subprocess.SubprocessError):
        raise SystemExit(2)
