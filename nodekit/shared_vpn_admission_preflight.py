#!/usr/bin/env python3
"""Read-only DE Xray / FI AmneziaWG admission capability probe.

Never change configuration, keys, routes, firewall or users. This cannot
grant / revoke sessions and is explicitly NOT a connection-limit enforcer.
Print no raw config, peer keys, user IDs, endpoints or IP addresses.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import sys
import time

DE_CONFIG = Path("/etc/mnebyvpn/xray-canary.json")
FI_AWG = "/opt/mnebyvpn-amneziawg/awg"
NODE = {"DE": "de-existing", "FI": "fi-test-01"}
PUB = re.compile(r"^[A-Za-z0-9+/]{43}=$")
MAX_CONFIG = 2 * 1024 * 1024
MAX_DUMP = 300 * 1024


class ObservationError(ValueError):
    pass


def _public_key(value: str) -> bool:
    if not isinstance(value, str) or not PUB.fullmatch(value):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and any(raw) and base64.b64encode(raw).decode() == value
    except (ValueError, base64.binascii.Error):
        return False


def inspect_xray_config(config: object) -> dict:
    """Static capability only; do NOT interpret as actual running Xray state."""
    if not isinstance(config, dict):
        raise ObservationError("Invalid Xray config structure")
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or len(inbounds) > 32:
        raise ObservationError("Invalid Xray inbound list")
    vless = [x for x in inbounds if isinstance(x, dict)
             and x.get("protocol") == "vless"]
    if not vless:
        raise ObservationError("No VLESS inbound")
    clients = []
    for inbound in vless:
        settings = inbound.get("settings")
        if not isinstance(settings, dict) or not isinstance(settings.get("clients"), list):
            raise ObservationError("Missing VLESS client registry")
        for user in settings["clients"]:
            if not isinstance(user, dict):
                raise ObservationError("Invalid VLESS user")
            clients.append(user)
    if len(clients) > 5000:
        raise ObservationError("Unexpected client volume")
    # Xray user keys cannot be printed, and an email is NOT a physical device.
    usable_emails = all(isinstance(u.get("email"), str) and
                        0 < len(u["email"]) <= 256 for u in clients)
    if clients and len({u["email"] for u in clients if
                        isinstance(u.get("email"), str)}) != len(clients):
        usable_emails = False
    levels = {str(u.get("level", 0)) for u in clients}
    policy = config.get("policy", {})
    policy_levels = policy.get("levels", {}) if isinstance(policy, dict) else {}
    stats_enabled = "stats" in config and isinstance(config["stats"], dict)
    online_policy = (isinstance(policy_levels, dict) and
                     all(isinstance(policy_levels.get(level), dict) and
                         policy_levels[level].get("statsUserOnline") is True
                         for level in levels))
    api = config.get("api", {})
    tag = api.get("tag") if isinstance(api, dict) else None
    services = api.get("services", []) if isinstance(api, dict) else []
    local_api = (isinstance(tag, str) and bool(tag) and
                 isinstance(services, list) and "StatsService" in services and
                 any(isinstance(x, dict) and x.get("tag") == tag and
                     x.get("listen") == "127.0.0.1" and
                     type(x.get("port")) is int and
                     1 <= x["port"] <= 65535 for x in inbounds))
    routing = config.get("routing", {})
    rules = routing.get("rules", []) if isinstance(routing, dict) else []
    route_ok = (isinstance(rules, list) and isinstance(tag, str) and
                any(isinstance(rule, dict) and rule.get("outboundTag") == tag and
                    isinstance(rule.get("inboundTag"), list) and
                    tag in rule["inboundTag"] for rule in rules))
    return {
        "country": "DE", "transport": "vless",
        "vless_client_count_configured": len(clients),
        "configured_user_attribution": bool(clients and usable_emails),
        "stats_online_configured": bool(stats_enabled and online_policy and local_api and
                                         route_ok and usable_emails),
        "running_process_config_verified": False,
        "pre_connection_admission_hook_verified": False,
        "enforcement_ready": False,
        "assessment": "OBSERVATION_ONLY",
    }


def inspect_awg_dump(raw: str, *, now: int) -> dict:
    """A recent handshake is a hint, NOT an active authenticated session."""
    if not isinstance(raw, str) or len(raw.encode("utf8")) > MAX_DUMP:
        raise ObservationError("Invalid AWG status length")
    lines = raw.rstrip("\n").splitlines()
    # AWG 3.1 pinned tools output 29 interface columns, not WG's 4.
    # Official pinned src/show.c::dump_print; peer lines remain 8 columns.
    if not lines or len(lines) > 1005 or len(lines[0].split("\t")) != 29:
        raise ObservationError("Invalid AWG status header")
    seen: set[str] = set()
    recent = 0
    unknown = 0
    for row in lines[1:]:
        parts = row.split("\t")
        if len(parts) != 8 or not _public_key(parts[0]) or parts[0] in seen:
            raise ObservationError("Malformed or duplicate AWG peer")
        seen.add(parts[0])
        if (not parts[4].isdigit() or not parts[5].isdigit() or
                not parts[6].isdigit()):
            raise ObservationError("Invalid AWG peer counters")
        stamp, rx, tx = (int(parts[4]), int(parts[5]), int(parts[6]))
        if stamp > now + 60 or rx < 0 or tx < 0:
            raise ObservationError("Invalid AWG handshake time")
        if stamp and 0 <= now - stamp <= 180:
            recent += 1
        else:
            unknown += 1
    return {
        "country": "FI", "transport": "amneziawg",
        "configured_peer_count": len(seen),
        "recent_handshake_peers_not_sessions": recent,
        "stale_or_never_handshaken_peers": unknown,
        "client_entitlement_binding_verified": False,
        "pre_connection_admission_hook_verified": False,
        "enforcement_ready": False,
        "assessment": "OBSERVATION_ONLY",
    }


def observe_de(path: Path = DE_CONFIG) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ObservationError("Expected Xray config absent")
    if not 1 <= path.stat().st_size <= MAX_CONFIG:
        raise ObservationError("Xray config invalid size")
    try:
        return inspect_xray_config(json.loads(path.read_text("utf8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ObservationError("Unreadable Xray config") from exc


def observe_fi(*, now: int | None = None, runner=subprocess.run) -> dict:
    try:
        output = runner(
            [FI_AWG, "show", "awg0", "dump"], capture_output=True,
            text=True, check=True, timeout=8)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ObservationError("AWG local status unavailable") from exc
    return inspect_awg_dump(output.stdout,
                            now=int(time.time()) if now is None else now)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--country", choices=("DE", "FI"), required=True)
    args = parser.parse_args(argv)
    try:
        report = observe_de() if args.country == "DE" else observe_fi()
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (ObservationError, OSError, TypeError, ValueError):
        # Never print private Xray/AWG config or local command stderr.
        print(json.dumps({"country": args.country, "assessment": "BLOCKED",
                          "enforcement_ready": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
