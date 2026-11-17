#!/usr/bin/env python3
"""Move an unpublished Nodekit VPS to its canonical country FQDN.

For the one already-staged FI test VPS only. This changes the advertised
hostname, not node_id or any Ed25519/REALITY/AmneziaWG private key. It does not
modify public DNS, enable services, configure customers, or publish receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

from install_components import safe_dir, safe_manifest, digest
from nodekit import validate_spec

STAGE_ROOT = Path("/var/lib/mnebyvpn-nodekit")
HOST_PATTERN = re.compile(r"[a-z]{2}\.mnebyvpn\.site\Z")
OLD_HOST = "fi-test.mnebyvpn.site"
NEW_HOST = "fi.mnebyvpn.site"
EXPECTED_IP = "217.11.167.91"
NODE_ID = "fi-test-01"  # Internal ID stays stable; customers only see canonical FQDN.


class RenameError(ValueError):
    pass


def canonical(spec: dict) -> str:
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def rebuild_spec(manifest: dict, hostname: str) -> dict:
    spec = {
        "schema_version": 1,
        "node_id": manifest.get("node_id"),
        "role": "combined",
        "services": manifest.get("roles"),
        "advertise_host": hostname,
        "listeners": manifest.get("listeners"),
    }
    return validate_spec(spec)


def validate_dns(hostname: str, expected_ip: str, *, resolver=socket.getaddrinfo) -> list[str]:
    if not HOST_PATTERN.fullmatch(hostname):
        raise RenameError("Country hostname must be exactly xx.mnebyvpn.site")
    if str(ipaddress.IPv4Address(expected_ip)) != EXPECTED_IP:
        raise RenameError("Unexpected VPS IPv4")
    try:
        answers = sorted({record[4][0] for record in resolver(
            hostname, None, family=socket.AF_INET)})
    except OSError as exc:
        raise RenameError("Country hostname does not resolve") from exc
    if answers != [expected_ip]:
        raise RenameError("Country hostname points to another VPS or multiple IPs")
    return answers


def checked_file(path: Path, *, limit: int = 50000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RenameError("Staged file missing or symlinked")
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > limit:
        raise RenameError("Staged file has unsafe owner, permissions or size")
    return path.read_bytes()


def plan(manifest: dict, vpn: dict, dns: dict, nginx_text: str,
         core_text: str, *, old_host: str = OLD_HOST, new_host: str = NEW_HOST) -> dict:
    if (manifest.get("node_id") != NODE_ID or
            manifest.get("state") != "testing" or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False or
            vpn.get("node_id") != NODE_ID or vpn.get("state") != "staged" or
            vpn.get("activation_enabled") is not False or
            vpn.get("vpn_users_enabled") is not False or
            dns.get("node_id") != NODE_ID or dns.get("state") != "staged" or
            dns.get("activation_enabled") is not False or
            dns.get("open_proxy_enabled") is not False or
            dns.get("personal_dns_enabled") is not False or
            dns.get("route_count") != 0 or
            not isinstance(dns.get("config_sha256"), dict)):
        raise RenameError("Only inactive empty test VPS may change hostname")
    if manifest.get("advertise_host") != old_host or vpn.get("advertise_host") != old_host:
        raise RenameError("Existing hostname unexpected")

    old_spec = rebuild_spec(manifest, old_host)
    old_hash = hashlib.sha256(canonical(old_spec).encode()).hexdigest()
    if manifest.get("spec_sha256") != old_hash:
        raise RenameError("Original immutable Nodekit spec SHA mismatch")
    if (dns["config_sha256"].get("nginx.conf") != hashlib.sha256(nginx_text.encode()).hexdigest()
            or dns["config_sha256"].get("Corefile") != hashlib.sha256(core_text.encode()).hexdigest()):
        raise RenameError("Staged DNS/proxy config hash mismatch")
    old_line = f"    {old_host} 127.0.0.1:8853;"
    if nginx_text.count(old_line) != 1:
        raise RenameError("DNS SNI rule was unexpectedly modified")
    new_nginx = nginx_text.replace(old_line, f"    {new_host} 127.0.0.1:8853;")
    new_manifest = dict(manifest, advertise_host=new_host)
    new_manifest["spec_sha256"] = hashlib.sha256(
        canonical(rebuild_spec(new_manifest, new_host)).encode()).hexdigest()
    new_vpn = dict(vpn, advertise_host=new_host)
    new_dns = dict(dns, config_sha256=dict(
        dns["config_sha256"],
        **{"nginx.conf": hashlib.sha256(new_nginx.encode()).hexdigest()},
    ))
    return {
        "manifest.json": new_manifest,
        "vpn/vpn-stage-manifest.json": new_vpn,
        "dns-proxy/manifest.json": new_dns,
        "dns-proxy/nginx.conf": new_nginx,
    }


def as_bytes(value: object) -> bytes:
    if isinstance(value, str):
        return value.encode()
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()


def atomic_write(path: Path, content: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".hostname-update-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def migrate(root: Path, node_id: str, *, resolver=socket.getaddrinfo,
            runner=subprocess.run) -> dict:
    if os.geteuid() != 0 or node_id != NODE_ID:
        raise RenameError("Migration is restricted to root on FI testing VPS")
    validate_dns(NEW_HOST, EXPECTED_IP, resolver=resolver)
    safe_dir(root)
    node = root / NODE_ID
    safe_dir(node)
    safe_dir(node / "vpn")
    safe_dir(node / "dns-proxy")
    safe_dir(node / "identity")
    safe_dir(node / "amneziawg")

    # No service may be running while an independent staging identity is renamed.
    for service in ("nginx.service", f"mnebyvpn-nodekit-vpn@{NODE_ID}.service",
                    "awg-quick@awg0.service", "mnebyvpn-nodekit-dns.service"):
        status = runner(["systemctl", "is-active", "--quiet", service],
                        timeout=12, check=False, capture_output=True)
        if status.returncode == 0:
            raise RenameError("Refusing hostname update while service is running")

    identity = checked_file(node / "identity" / "node-public.spki", limit=44)
    if len(identity) != 44:
        raise RenameError("Node Ed25519 identity not initialized")
    identity_sha = hashlib.sha256(identity).hexdigest()
    manifest = safe_manifest(node / "manifest.json")
    vpn = safe_manifest(node / "vpn" / "vpn-stage-manifest.json")
    dns = safe_manifest(node / "dns-proxy" / "manifest.json")
    nginx_text = checked_file(node / "dns-proxy" / "nginx.conf").decode()
    core_text = checked_file(node / "dns-proxy" / "Corefile").decode()
    if (manifest.get("advertise_host") == NEW_HOST and
            vpn.get("advertise_host") == NEW_HOST and
            f"    {NEW_HOST} 127.0.0.1:8853;" in nginx_text):
        if (manifest.get("spec_sha256") != hashlib.sha256(
                canonical(rebuild_spec(manifest, NEW_HOST)).encode()).hexdigest()
                or dns.get("config_sha256", {}).get("nginx.conf") !=
                hashlib.sha256(nginx_text.encode()).hexdigest()):
            raise RenameError("Post-migration stage drift")
        return {"hostname": NEW_HOST, "node_id": NODE_ID, "already_migrated": True,
                "identity_unchanged_sha256": identity_sha, "published": False}

    changes = plan(manifest, vpn, dns, nginx_text, core_text)
    # Candidate syntax check before modifying any state or enabling any listener.
    with tempfile.TemporaryDirectory(prefix=".hostname-check-", dir=node) as scratch:
        file = Path(scratch) / "nginx.conf"
        file.write_text(changes["dns-proxy/nginx.conf"])
        file.chmod(0o600)
        runner(["nginx", "-t", "-c", str(file)], timeout=20, check=True,
               capture_output=True)

    previous = {name: checked_file(node / name) for name in changes}
    updated: list[str] = []
    try:
        for name, value in changes.items():
            atomic_write(node / name, as_bytes(value))
            updated.append(name)
        # Verify key remained in place and all manifests are the intended state.
        if digest(node / "identity" / "node-public.spki") != identity_sha:
            raise RenameError("Identity changed during hostname migration")
        for name, value in changes.items():
            if checked_file(node / name) != as_bytes(value):
                raise RenameError("Failed to verify staged hostname changes")
    except BaseException:
        for name in reversed(updated):
            atomic_write(node / name, previous[name])
        raise
    return {"hostname": NEW_HOST, "node_id": NODE_ID,
            "identity_unchanged_sha256": identity_sha,
            "dns_sni_staged": True, "vpn_hostname_updated": True,
            "activation_enabled": False, "published": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--stage-root", type=Path, default=STAGE_ROOT)
    args = parser.parse_args()
    try:
        print(json.dumps(migrate(args.stage_root, args.node_id), sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError) as exc:
        print("nodekit_hostname_migration_error=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
