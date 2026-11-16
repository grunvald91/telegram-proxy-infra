#!/usr/bin/env python3
"""Scoped local runbook executor for *new nodekit-owned* sidecars only.

No arbitrary shell commands and no access to shared 89/188 services. An AI
model cannot create an authorized permit. Production auto-repair remains off
until per-node activation and independent external E2E verification exist.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import uuid

from control_plane import ContractError, canonical, utc_time
from incident_gateway import private_secret

SERVICES = frozenset({"dns", "vpn", "proxy"})
REASON = "OWNED_UNIT_INACTIVE"
NODE_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
OPID_RE = re.compile(r"[0-9a-f-]{36}\Z")


def verify_permit(permit: dict, signing_key: bytes, node_id: str,
                  now: datetime) -> str:
    names = {"operation_id", "incident_id", "node_id", "service",
             "reason_code", "action", "issued_at", "expires_at", "mac"}
    if not isinstance(permit, dict) or set(permit) != names:
        raise ContractError("Invalid runbook permit")
    if (not NODE_RE.fullmatch(node_id) or permit["node_id"] != node_id or
            permit["action"] != "restart-owned-sidecar" or
            permit["reason_code"] != REASON or
            permit["service"] not in SERVICES):
        raise ContractError("Runbook not within owned service scope")
    for field in ("operation_id", "incident_id"):
        try:
            if str(uuid.UUID(permit[field])) != permit[field]:
                raise ContractError("Non-canonical UUID")
        except (TypeError, ValueError, AttributeError) as exc:
            raise ContractError("Invalid permit ID") from exc
    issued, expires = utc_time(permit["issued_at"]), utc_time(permit["expires_at"])
    if (issued > now + timedelta(seconds=30) or
            expires <= now or expires - issued > timedelta(minutes=2) or
            now - issued > timedelta(minutes=2)):
        raise ContractError("Runbook permit expired or too broad")
    mac = permit["mac"]
    if not isinstance(mac, str) or not re.fullmatch(r"[a-f0-9]{64}", mac):
        raise ContractError("Missing permit signature")
    unsigned = {k: v for k, v in permit.items() if k != "mac"}
    expected = hmac.new(signing_key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        raise ContractError("Runbook permit signature mismatch")
    return "mnebyvpn-nodekit-" + node_id + "-" + permit["service"] + ".service"


def ledger_reserve(db_path: Path, incident_id: str, operation_id: str) -> bool:
    if db_path.is_symlink() or not db_path.parent.is_dir() or db_path.parent.stat().st_mode & 0o022:
        raise ContractError("Unsafe operations ledger")
    with sqlite3.connect(db_path, timeout=8, isolation_level=None) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS operations "
                   "(incident_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL,"
                   " started_at TEXT NOT NULL)")
        cursor = db.execute(
            "INSERT OR IGNORE INTO operations VALUES(?,?,?)",
            (incident_id, operation_id, datetime.now(timezone.utc).isoformat()))
        db.execute("COMMIT")
        fresh = cursor.rowcount == 1
    db_path.chmod(0o600)
    return fresh


def execute(permit: dict, key: bytes, node_id: str,
            ledger_path: Path, enabled: bool, now: datetime,
            command_runner=subprocess.run) -> dict:
    unit = verify_permit(permit, key, node_id, now)
    result = {"operation_id": permit["operation_id"], "incident_id": permit["incident_id"],
              "unit": unit, "action": "restart-owned-sidecar",
              "resolved": False, "external_e2e_verified": False}
    if not enabled:
        return {**result, "status": "disabled"}
    if os.geteuid() != 0:
        raise ContractError("Runbook executor must be managed by a privileged service")
    # One automatic attempt per incident. Never restart shared nginx/xray/wg.
    if not ledger_reserve(ledger_path, permit["incident_id"], permit["operation_id"]):
        return {**result, "status": "duplicate"}
    check = command_runner(["/usr/bin/systemctl", "is-active", "--quiet", unit],
                           capture_output=True, timeout=5, check=False)
    if check.returncode == 0:
        return {**result, "status": "already_active_no_action"}
    restart = command_runner(["/usr/bin/systemctl", "restart", unit],
                             capture_output=True, timeout=15, check=False)
    if restart.returncode != 0:
        return {**result, "status": "restart_failed_escalate"}
    health = command_runner(["/usr/bin/systemctl", "is-active", "--quiet", unit],
                            capture_output=True, timeout=5, check=False)
    if health.returncode != 0:
        return {**result, "status": "unit_not_active_escalate"}
    # Unit health alone is NOT confirmation that data flows; external probes
    # must perform another test and independently mark incident resolved.
    return {**result, "status": "locally_restarted_pending_external_probe"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--permit", type=Path, required=True)
    ap.add_argument("--key-file", type=Path, required=True)
    ap.add_argument("--ledger", type=Path, required=True)
    ap.add_argument("--node-id", required=True)
    ap.add_argument("--enable-marker", type=Path,
                    default=Path("/etc/mnebyvpn-nodekit/auto-repair-enabled"))
    args = ap.parse_args()
    try:
        if args.permit.is_symlink() or not args.permit.is_file() or args.permit.stat().st_size > 4096:
            raise ContractError("Invalid permit file")
        key = private_secret(args.key_file)
        now = datetime.now(timezone.utc)
        permit = json.loads(args.permit.read_text(encoding="utf-8"))
        # Non-root or writable markers cannot enable automatic repair.
        marker_ok = (
            args.enable_marker.is_file() and
            not args.enable_marker.is_symlink() and
            args.enable_marker.stat().st_uid == 0 and
            args.enable_marker.stat().st_mode & 0o022 == 0 and
            args.enable_marker.read_text(encoding="utf-8").strip() == "enabled"
        )
        result = execute(permit, key, args.node_id, args.ledger, marker_ok, now)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] in (
            "disabled", "duplicate", "already_active_no_action",
            "locally_restarted_pending_external_probe") else 2
    except (ContractError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("runbook_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
