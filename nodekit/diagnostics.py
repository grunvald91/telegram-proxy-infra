#!/usr/bin/env python3
"""Read-only, bounded nodekit diagnostic evidence for escalation.

Reports metrics and configuration SHA-256 only; never secrets, log contents,
DNS subscriber identities, connection logs or customer VPN credentials.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from control_plane import ContractError

ALLOWED_COMPONENTS = frozenset({"dns", "vpn", "proxy"})


def read_memory() -> dict:
    allowed = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    result = {}
    with open("/proc/meminfo", encoding="ascii") as source:
        for line in source:
            key, sep, amount = line.partition(":")
            if sep and key in allowed:
                result[key + "_kib"] = int(amount.strip().split()[0])
    return result


def config_fingerprint(file: Path, expected_sha256: str) -> dict:
    if (not isinstance(expected_sha256, str) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        raise ContractError("Expected configuration hash missing")
    if not file.is_file() or file.is_symlink():
        return {"present": False, "matches_known_good": False}
    if file.stat().st_size > 4 * 1024 * 1024:
        raise ContractError("Diagnostic hashing limited to 4 MiB per config")
    digest = hashlib.sha256()
    with file.open("rb") as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    actual = digest.hexdigest()
    return {"present": True, "sha256": actual,
            "matches_known_good": actual == expected_sha256}


def report(node_id: str, expected: dict[str, dict[str, str]],
           command_runner=subprocess.run) -> dict:
    if (not isinstance(node_id, str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,39}", node_id)):
        raise ContractError("Invalid node ID")
    if not isinstance(expected, dict) or len(expected) > 32:
        raise ContractError("Invalid configuration inventory")
    results = {}
    for alias, item in expected.items():
        if (not isinstance(alias, str) or not re.fullmatch(r"[a-z0-9_-]{1,40}", alias) or
                not isinstance(item, dict) or set(item) != {"path", "sha256"}):
            raise ContractError("Invalid fingerprint item")
        filename = item["path"]
        base = Path("/etc/mnebyvpn-nodekit")
        path = Path(filename) if isinstance(filename, str) else Path("/")
        if (not isinstance(filename, str) or not path.is_absolute() or
                base.is_symlink() or not path.resolve().is_relative_to(base.resolve()) or
                path.name.lower().endswith((".key", ".pem", ".env", ".secret"))):
            raise ContractError("Only non-secret nodekit-owned configuration may be fingerprinted")
        results[alias] = config_fingerprint(path, item["sha256"])
    units = {}
    for service in sorted(ALLOWED_COMPONENTS):
        name = "mnebyvpn-nodekit-" + node_id + "-" + service + ".service"
        status = command_runner(
            ["/usr/bin/systemctl", "is-active", "--quiet", name],
            capture_output=True, check=False, timeout=5)
        units[service] = {"active": status.returncode == 0}
    disk = shutil.disk_usage("/")
    return {
        "schema_version": 1,
        "node_id": node_id,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "component_units": units,
        "config_hashes": results,
        "resources": {
            "cpu_count": os.cpu_count(),
            "load_1_5_15": [round(v, 2) for v in os.getloadavg()],
            "disk_total_gib": round(disk.total / (1024 ** 3), 2),
            "disk_free_gib": round(disk.free / (1024 ** 3), 2),
            **read_memory(),
        },
        "contains_customer_data": False,
        "external_application_e2e_verified": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node-id", required=True)
    ap.add_argument("--known-good", required=True, type=Path)
    args = ap.parse_args()
    try:
        if (args.known_good.is_symlink() or not args.known_good.is_file() or
                args.known_good.stat().st_size > 16384):
            raise ContractError("Invalid known-good inventory")
        expected = json.loads(args.known_good.read_text(encoding="utf-8"))
        print(json.dumps(report(args.node_id, expected), sort_keys=True))
        return 0
    except (ValueError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
        print("node_diagnostic_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
