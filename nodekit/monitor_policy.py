#!/usr/bin/env python3
"""Central alert policy for periodic independent probe observations.

Collector deployment and authenticated transport are separate. Do NOT ingest
arbitrary user-submitted observations. Agent receives only normalized codes.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
from uuid import NAMESPACE_URL, uuid5

from control_plane import ContractError, canonical, utc_time
from incident_gateway import private_secret


PROBE_TYPES = frozenset({"external_vpn_e2e", "external_dns_e2e",
                         "external_proxy_e2e", "owned_sidecar_process"})
SERVICE_PROBE = {
    "vpn": "external_vpn_e2e",
    "dns": "external_dns_e2e",
    "sni-proxy": "external_proxy_e2e",
}
WINDOW = timedelta(minutes=5)


def parse_observation(raw: dict, now: datetime) -> dict:
    keys = {"node_id", "service", "observer", "probe", "ok", "observed_at"}
    if not isinstance(raw, dict) or set(raw) != keys:
        raise ContractError("Invalid probe observation")
    if (not isinstance(raw["node_id"], str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,39}", raw["node_id"]) or
            raw["service"] not in SERVICE_PROBE or
            not isinstance(raw["observer"], str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,39}", raw["observer"]) or
            raw["probe"] not in PROBE_TYPES or
            type(raw["ok"]) is not bool):
        raise ContractError("Invalid probe fields")
    stamp = utc_time(raw["observed_at"])
    if now - stamp > WINDOW or stamp > now + timedelta(seconds=30):
        raise ContractError("Stale/future probe result")
    return {**raw, "timestamp": stamp}


def detect_incident(records: list[dict], approved_nodes: set[str],
                    now: datetime) -> dict | None:
    if len(records) > 500:
        raise ContractError("Too many observations in one batch")
    by_node = defaultdict(list)
    for raw in records:
        item = parse_observation(raw, now)
        if item["node_id"] not in approved_nodes:
            raise ContractError("Unknown monitoring node")
        by_node[(item["node_id"], item["service"])].append(item)
    affected = []
    for (node, service), items in sorted(by_node.items()):
        probe_name = SERVICE_PROBE[service]
        groups = defaultdict(list)
        for sample in items:
            if sample["probe"] == probe_name:
                groups[sample["observer"]].append(sample)
        # Two independent approved external observers, each with at least two
        # fresh failed samples; single DNS/TCP handshake cannot assert app E2E.
        failing = []
        for observer, samples in groups.items():
            latest = sorted(samples, key=lambda v: v["timestamp"], reverse=True)[:2]
            if (len(latest) == 2 and not latest[0]["ok"] and not latest[1]["ok"] and
                    latest[0]["timestamp"] != latest[1]["timestamp"]):
                failing.append(observer)
        if len(failing) < 2:
            continue
        # Self-reported process state is additional evidence, not a second
        # independent external observer. Never restart an active unit because
        # two clients experienced an ISP/DPI problem.
        down = any(x["probe"] == "owned_sidecar_process" and
                   x["observer"] == "nodekit-local" and not x["ok"] for x in items)
        affected.append((node, service, down, len(failing)))
    if not affected:
        return None
    nodes = sorted({n for n, _, _, _ in affected})
    services = sorted({s for _, s, _, _ in affected})
    kind = ("owned_sidecar_down" if len(affected) == 1 and affected[0][2]
            else "cross_node_outage" if len(nodes) > 1
            else "data_path_broken")
    code = ("OWNED_UNIT_INACTIVE" if kind == "owned_sidecar_down"
            else "CROSS_NODE_FAILURE" if kind == "cross_node_outage"
            else "EXTERNAL_E2E_FAILURE")
    # Stable incident ID within ten-minute window to avoid alert storms.
    bucket = int(now.timestamp()) // 600
    stable_id = str(uuid5(NAMESPACE_URL, "mnebyvpn-alert:"+str(bucket)+":"+
                          ",".join(nodes)+":"+kind+":"+",".join(services)))
    return {
        "incident_id": stable_id, "kind": kind,
        "nodes": nodes, "services": services,
        "independent_probes": min(v[3] for v in affected),
        "repeated_failures": 2, "detail_code": code
    }


def sign_event(incident: dict, key: bytes, now: datetime) -> dict:
    if len(key) < 32:
        raise ContractError("Invalid central signing key")
    unsigned = {
        "incident": incident,
        "observed_at": now.isoformat(),
        "nonce": secrets.token_hex(16)
    }
    return {**unsigned, "mac": hmac.new(key, canonical(unsigned),
                                         hashlib.sha256).hexdigest()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--observations", type=Path, required=True)
    ap.add_argument("--approved-node", action="append", required=True)
    ap.add_argument("--ingest-key-file", type=Path, required=True)
    args = ap.parse_args()
    try:
        if (args.observations.is_symlink() or not args.observations.is_file()
                or args.observations.stat().st_size > 131072):
            raise ContractError("Unsafe observations file")
        data = json.loads(args.observations.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ContractError("Expected observation list")
        now = datetime.now(timezone.utc)
        incident = detect_incident(data, set(args.approved_node), now)
        if incident is None:
            print('{"incident":null,"status":"no_confirmed_outage"}')
            return 0
        envelope = sign_event(incident, private_secret(args.ingest_key_file), now)
        print(json.dumps(envelope, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print("monitor_policy_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
