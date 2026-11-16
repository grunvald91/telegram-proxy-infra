#!/usr/bin/env python3
"""Authenticated incident ingestion + external advisory agent API.

Run only on a separate private control host. This is NOT a daemon or an
automatic repair executor. Real service monitoring and dispatch must call it.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError

from control_plane import (
    ContractError, Incident, canonical, parse_agent_advice, route_incident,
    safe_agent_payload, utc_time,
)


def private_secret(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ContractError("Secret must be a regular file")
    st = path.stat()
    if (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0 or st.st_uid != os.geteuid():
        raise ContractError("Secret must be owned by this process and mode 0600")
    value = path.read_bytes().strip()
    if len(value) < 32 or len(value) > 4096:
        raise ContractError("Invalid private secret length")
    return value


def validate_envelope(value: dict, key: bytes, at: datetime) -> Incident:
    if not isinstance(value, dict) or set(value) != {"incident", "observed_at", "nonce", "mac"}:
        raise ContractError("Invalid authenticated event envelope")
    if not isinstance(value["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["nonce"]):
        raise ContractError("Invalid event nonce")
    if not isinstance(value["mac"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["mac"]):
        raise ContractError("Invalid event signature")
    unsigned = {k: value[k] for k in ("incident", "observed_at", "nonce")}
    expected = hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, value["mac"]):
        raise ContractError("Invalid event signature")
    observed = utc_time(value["observed_at"])
    if abs((at - observed).total_seconds()) > 300:
        raise ContractError("Stale/future event")
    return Incident.parse(value["incident"])


def agent_url(value: str, pinned_hostname: str) -> str:
    if not isinstance(value, str) or not isinstance(pinned_hostname, str):
        raise ContractError("Agent endpoint not configured")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or
            parsed.hostname.lower() != pinned_hostname.lower() or
            parsed.username or parsed.password or parsed.fragment or
            parsed.query or not parsed.path.startswith("/") or
            parsed.path.startswith("//") or len(value) > 512):
        raise ContractError("Agent API HTTPS URL must match exact configured hostname")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ContractError("IP literal agent endpoints are not allowed")
    if parsed.port not in (None, 443):
        raise ContractError("Only default TLS port permitted")
    if not re.fullmatch(r"[A-Za-z0-9.-]{4,253}", pinned_hostname) or "." not in pinned_hostname:
        raise ContractError("Invalid pinned hostname")
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ContractError("Agent endpoint must not redirect")


def send_agent(payload: dict, url: str, hostname: str,
               bearer: bytes, sender=None) -> dict[str, str]:
    agent_url(url, hostname)
    if len(bearer) < 32:
        raise ContractError("Agent API token missing")
    content = canonical(payload)
    if len(content) > 4096:
        raise ContractError("Agent request exceeds bounded size")
    req = Request(url, data=content, method="POST",
                  headers={"Content-Type": "application/json",
                           "Authorization": "Bearer " + bearer.decode("ascii"),
                           "Idempotency-Key": payload["incident_id"]})
    # Caller can supply fake sender in unit tests; production refuses redirects.
    open_request = sender if sender is not None else build_opener(NoRedirect()).open
    with open_request(req, timeout=7) as reply:
        if reply.status != 200 or reply.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise ContractError("Unexpected agent API reply")
        raw = reply.read(4097)
        if len(raw) > 4096:
            raise ContractError("Oversized agent reply")
        result = json.loads(raw)
    if not isinstance(result, dict):
        raise ContractError("Malformed agent advice")
    # Result is deliberately advisory, never commands/SQL, no system access.
    return result


def register_incident(db_path: Path, incident_id: str, decision: dict,
                      at: datetime) -> bool:
    """Durable dedup; one error event triggers one advisory API invocation."""
    if db_path.is_symlink():
        raise ContractError("Refusing symlink SQLite DB")
    if not db_path.parent.is_dir() or db_path.parent.stat().st_mode & 0o022:
        raise ContractError("State directory must exist and not be writable by others")
    with sqlite3.connect(db_path, timeout=8) as db:
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("CREATE TABLE IF NOT EXISTS incidents "
                   "(incident_id TEXT PRIMARY KEY, decision_json TEXT NOT NULL, "
                   "observed_at TEXT NOT NULL)")
        cursor = db.execute(
            "INSERT OR IGNORE INTO incidents(incident_id, decision_json, observed_at) VALUES(?,?,?)",
            (incident_id, json.dumps(decision, sort_keys=True), at.isoformat()))
        db.commit()
        created = cursor.rowcount == 1
    db_path.chmod(0o600)
    return created


def dispatch(envelope: dict, secret: bytes, owned_nodes: set[str],
             db_path: Path, now: datetime, send=None) -> dict:
    event = validate_envelope(envelope, secret, now)
    decision = route_incident(event, owned_nodes)
    created = register_incident(db_path, event.incident_id, decision, now)
    if not created:
        return {"incident_id": event.incident_id, "deduplicated": True, "decision": decision}
    payload = safe_agent_payload(event, decision)
    result: dict = {"incident_id": event.incident_id, "deduplicated": False,
                    "decision": decision, "payload": payload, "agent_invoked": False}
    if send is not None:
        advice = send(payload)
        result["advice"] = parse_agent_advice(advice, decision)
        result["agent_invoked"] = True
    # Integration must deliver an owner notification; this return is not delivery proof.
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--ingest-key-file", type=Path, required=True)
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--owned-node", action="append", default=[])
    parser.add_argument("--agent-url", default="")
    parser.add_argument("--agent-hostname", default="")
    parser.add_argument("--agent-key-file", type=Path)
    args = parser.parse_args()
    try:
        if args.envelope.is_symlink() or not args.envelope.is_file() or args.envelope.stat().st_size > 8192:
            raise ContractError("Event envelope must be a bounded regular file")
        envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
        key = private_secret(args.ingest_key_file)
        # Both url and key must be explicitly configured for agent dispatch.
        if bool(args.agent_url) != bool(args.agent_key_file):
            raise ContractError("Agent URL and key file must be provided together")
        sender = None
        if args.agent_url:
            agent_url(args.agent_url, args.agent_hostname)
            token = private_secret(args.agent_key_file)
            sender = lambda payload: send_agent(payload, args.agent_url, args.agent_hostname, token)
        output = dispatch(envelope, key, set(args.owned_node), args.state_db,
                          datetime.now(timezone.utc), sender)
        # This JSON is safe: no raw logs, profiles, or secrets.
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError, HTTPError, URLError) as exc:
        # Never echo untrusted content, URLs or secrets into the log.
        print("incident_controller_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
