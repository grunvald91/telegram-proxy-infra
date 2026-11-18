#!/usr/bin/env python3
"""Validate a reviewed, non-secret per-country Nodekit fleet inventory entry.

Only the committed inventory (never an event's IP/hostname) decides the SSH
destination. This code creates no VPS, exposes no credentials, enables no
subscriber and makes no changes to a running service.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

from nodekit import validate_spec

ROOT = Path(__file__).resolve().parent / "fleet"
COUNTRY = re.compile(r"[a-z]{2}\Z")
NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
PROTECTED = {"89.125.90.101", "188.120.254.223"}
SERVICES = ["dns", "vpn", "sni-proxy", "tunnel"]
LISTENERS = {
    "dot_tcp": 853, "vpn_tcp": 2053,
    "sni_tcp": 443, "tunnel_udp": 51820,
}


class FleetError(ValueError):
    pass


def inventory(root: Path, country: str) -> tuple[dict, dict]:
    if not COUNTRY.fullmatch(country):
        raise FleetError("Country must be two lowercase letters")
    source = root / (country + ".json")
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 4096:
        raise FleetError("Reviewed fleet entry is unavailable or too large")
    config = json.loads(source.read_text(encoding="utf-8"))
    fields = {
        "schema_version", "country_code", "node_id", "advertise_host",
        "ssh_ipv4", "role", "services", "listeners", "status",
        "automatic_bootstrap_allowed", "subscriber_publication_allowed",
        "expected_identity_public_sha256",
    }
    if not isinstance(config, dict) or set(config) != fields:
        raise FleetError("Fleet entry has unknown or missing fields")
    if config["schema_version"] != 1 or config["country_code"] != country.upper():
        raise FleetError("Invalid country or inventory version")
    name = config["node_id"]
    if not isinstance(name, str) or not NODE.fullmatch(name) or name.endswith("-"):
        raise FleetError("Invalid immutable node identifier")
    host = config["advertise_host"]
    if host != country + ".mnebyvpn.site":
        raise FleetError("Customer-facing name must be xx.mnebyvpn.site")
    addr = config["ssh_ipv4"]
    if not isinstance(addr, str):
        raise FleetError("Missing VPS IPv4")
    try:
        parsed = ipaddress.IPv4Address(addr)
    except ipaddress.AddressValueError as exc:
        raise FleetError("Invalid public VPS IPv4") from exc
    if str(parsed) != addr or not parsed.is_global or addr in PROTECTED:
        raise FleetError("Private, protected or noncanonical target forbidden")
    if config["status"] not in ("testing", "approved"):
        raise FleetError("No automatic bootstrap for active, revoked or planned nodes")
    if config["automatic_bootstrap_allowed"] is not True:
        raise FleetError("Inventory requires explicit owner approval")
    if config["subscriber_publication_allowed"] is not False:
        raise FleetError("Bootstrap must never publish subscriber credentials")
    if (config["role"] != "combined" or config["services"] != SERVICES or
            config["listeners"] != LISTENERS):
        raise FleetError("Unexpected ports or roles: separate release required")
    identity = config["expected_identity_public_sha256"]
    if identity is not None and (not isinstance(identity, str) or
                                 not SHA.fullmatch(identity)):
        raise FleetError("Pinned identity is malformed")
    spec = {
        "schema_version": 1, "node_id": name, "role": config["role"],
        "services": config["services"], "advertise_host": host,
        "listeners": config["listeners"],
    }
    validate_spec(spec)
    return config, spec


def write_spec(path: Path, spec: dict) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise FleetError("Spec destination must not already exist")
    old = os.umask(0o077)
    try:
        with path.open("x", encoding="utf-8") as output:
            json.dump(spec, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    finally:
        os.umask(old)
    if path.stat().st_mode & 0o077:
        raise FleetError("Nonprivate generated spec")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--country", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--write-spec", type=Path)
    args = parser.parse_args()
    try:
        entry, spec = inventory(args.root, args.country)
        if args.write_spec is not None:
            write_spec(args.write_spec, spec)
        report = {
            "country_code": entry["country_code"], "node_id": entry["node_id"],
            "advertise_host": entry["advertise_host"], "ssh_ipv4": entry["ssh_ipv4"],
            "expected_identity_public_sha256": entry["expected_identity_public_sha256"],
            "approved_for_nonpublishing_bootstrap": True, "published": False,
        }
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as error:
        print("nodekit_fleet_plan_error=" + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
