#!/usr/bin/env python3
"""Read-only FI217 Smart DNS deployment inventory, never server activation.

Print only booleans, counts, and stable status identifiers; never print private
keys, personal hostnames, controller grants, tokens or full service configs.
The one-shot GitHub workflow pins both RU188 and FI217 SSH host identities.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

NODE = "fi-test-01"
HOST = "fi.mnebyvpn.site"
ROOT = Path("/var/lib/mnebyvpn-nodekit") / NODE
REGIONAL_PROBES = (
    "aaaaaaaaaaaa.fi.dns.mnebyvpn.site",
    "bbbbbbbbbbbb.fi.dns.mnebyvpn.site",
)
CERT_CANDIDATES = (
    ROOT / "tls/fullchain.pem",
    ROOT / "dns-auth/fullchain.pem",
    Path("/etc/letsencrypt/live/fi.dns.mnebyvpn.site/fullchain.pem"),
    Path("/etc/letsencrypt/live/fi.mnebyvpn.site/fullchain.pem"),
)


def command(*args: str, timeout: int = 6) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout, check=False)


def secure_json(path: Path) -> dict | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        metadata = path.stat()
        if (metadata.st_uid != 0 or metadata.st_mode & 0o077 or
                not 1 <= metadata.st_size <= 100_000):
            return None
        parsed = json.loads(path.read_text())
        return parsed if isinstance(parsed, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def certificate_summary() -> dict:
    results = []
    for path in CERT_CANDIDATES:
        # Live Certbot symlinks to a root-owned immutable archive are expected.
        if not path.exists():
            continue
        canonical = path.resolve()
        if not canonical.is_file() or canonical.stat().st_uid != 0:
            continue
        valid_names = [
            command("openssl", "x509", "-in", str(path),
                    "-noout", "-checkhost", name).returncode == 0
            for name in REGIONAL_PROBES
        ]
        # openssl x509 -checkhost is not CA trust validation. Verify that
        # the actual presented leaf chains to the system trust store.
        chain_verified = command(
            "openssl", "verify", "-purpose", "sslserver",
            "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
            "-untrusted", str(path), str(path)).returncode == 0
        # Public key extraction only; never display private key or cert PEM.
        private = path.parent / "privkey.pem"
        key_match = False
        if private.exists():
            # DER is binary, so do NOT use the text-mode command() wrapper.
            try:
                from_key = subprocess.run([
                    "openssl", "pkey", "-in", str(private),
                    "-pubout", "-outform", "DER"],
                    capture_output=True, timeout=6)
                from_leaf_pem = subprocess.run([
                    "openssl", "x509", "-in", str(path),
                    "-pubkey", "-noout"],
                    capture_output=True, timeout=6)
                from_leaf_der = subprocess.run([
                    "openssl", "pkey", "-pubin", "-outform", "DER"],
                    input=from_leaf_pem.stdout,
                    capture_output=True, timeout=6)
                key_match = bool(from_key.returncode == 0 and
                    from_leaf_pem.returncode == 0 and
                    from_leaf_der.returncode == 0 and
                    from_leaf_der.stdout == from_key.stdout)
            except (OSError, subprocess.TimeoutExpired):
                key_match = False
        results.append({
            "ca_chain_verified": chain_verified,
            "certificate_key_match": key_match,
            "chain_pem_count": path.read_bytes().count(b"-----BEGIN CERTIFICATE-----"),
            "source": "nodekit_tls" if path == CERT_CANDIDATES[0]
            else "regional_dns_auth" if path == CERT_CANDIDATES[1]
            else "regional_acme" if path == CERT_CANDIDATES[2]
            else "country_acme",
            "regional_two_name_match": all(valid_names),
            "unexpired_14d": command("openssl", "x509", "-in", str(path),
                                    "-noout", "-checkend", str(14*86400)).returncode == 0,
        })
    return {
        "candidates": results,
        "regional_wildcard_present": any(
            c["regional_two_name_match"] and c["unexpired_14d"]
            for c in results),
    }


def listening_tcp_ports() -> list[int]:
    result = command("ss", "-H", "-lnt", timeout=8)
    if result.returncode != 0:
        return []
    ports = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        bound = parts[3]
        candidate = bound.rsplit(":", 1)[-1]
        if candidate.isdigit():
            number = int(candidate)
            if number in (53, 80, 443, 853, 8853, 18853):
                ports.add(number)
    return sorted(ports)


def systemd_active(unit: str) -> bool:
    if not re.fullmatch(r"[a-zA-Z0-9@_.-]{3,110}", unit):
        return False
    return command("systemctl", "is-active", "--quiet", unit).returncode == 0


def gather() -> dict:
    if os.geteuid() != 0:
        raise ValueError("Root needed for read-only private inventory")
    manifest = secure_json(ROOT / "manifest.json") or {}
    dns = secure_json(ROOT / "dns-proxy/manifest.json") or {}
    tls = secure_json(ROOT / "tls/manifest.json") or {}
    return {
        "node_id": NODE, "mode": "read_only",
        "hostname_matches_manifest": manifest.get("advertise_host") == HOST,
        "node_state": manifest.get("state") if manifest.get("state") in
        ("active", "testing") else "unverified",
        "dns_candidate_present": bool(dns),
        "dns_candidate_stage": dns.get("state") == "staged",
        "dns_candidate_route_count": dns.get("route_count") if
        type(dns.get("route_count")) is int and 0 <= dns["route_count"] <= 200
        else None,
        "tls_candidate_present": bool(tls),
        "tls_candidate_for_country_host": tls.get("hostname") == HOST,
        "regional_tls": certificate_summary(),
        "fi_dns_snapshot_present": (ROOT / "dns-auth/snapshot.json").is_file(),
        "fi_dns_rollback_fence_present":
            (ROOT / "dns-auth/snapshot-highwater.json").is_file(),
        "fi_controller_public_pin_present":
            (ROOT / "controller-access.spki").is_file(),
        "fi_coredns_binary_present": Path("/opt/coredns/coredns").is_file(),
        "fi_nginx_binary_present": command("nginx", "-v").returncode == 0,
        "tcp_ports_present": listening_tcp_ports(),
        "service_coredns_active": systemd_active(
            "mnebyvpn-nodekit-coredns@fi-test-01.service"),
        "service_fi_dot_guard_active":
            systemd_active("mnebyvpn-fi-personal-dot.service"),
        "public_release_authorized": False,
        "customer_settings_changed": False,
    }


def main() -> int:
    try:
        print(json.dumps(gather(), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("FI_DNS_INVENTORY_FAILED=true", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
