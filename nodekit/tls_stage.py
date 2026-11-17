#!/usr/bin/env python3
"""Issue and sync an ACME HTTP-01 certificate for an isolated Nodekit country VPS.

Only copies CA-trusted certificates into root-only staged TLS. Does NOT start
CoreDNS/Nginx, open listeners, touch firewall, or enroll customers. Certbot
must already be installed from the OS distro. Certbot controls renewal.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

ROOT = Path("/var/lib/mnebyvpn-nodekit")
COUNTRY_HOST = re.compile(r"[a-z]{2}\.mnebyvpn\.site\Z")
NODE_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
CERTBOT_ROOT = Path("/etc/letsencrypt")
MIN_REMAINING_SECONDS = 14 * 24 * 3600


class TLSStageError(ValueError):
    pass


def secure_dir(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise TLSStageError("Required private directory missing")
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise TLSStageError("Unsafe node directory")


def private_file(path: Path, limit: int = 50000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise TLSStageError("Untrusted staged file")
    meta = path.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o077 or not 1 <= meta.st_size <= limit:
        raise TLSStageError("Unsafe staged file permissions or size")
    return path.read_bytes()


def guarded_node(root: Path, node_id: str, host: str, ip: str,
                 *, resolver=socket.getaddrinfo) -> Path:
    if (os.geteuid() != 0 or not isinstance(node_id, str)
            or not NODE_ID.fullmatch(node_id) or node_id.endswith("-")
            or not isinstance(host, str) or not COUNTRY_HOST.fullmatch(host)):
        raise TLSStageError("Root, valid node ID and country domain are required")
    public_ip = ipaddress.ip_address(ip)
    if not isinstance(public_ip, ipaddress.IPv4Address) or not public_ip.is_global:
        raise TLSStageError("Expected public IPv4 address is required")
    responses = set()
    try:
        for item in resolver(host, None, family=socket.AF_INET):
            responses.add(item[4][0])
    except OSError as exc:
        raise TLSStageError("Country hostname not resolvable") from exc
    if responses != {ip}:
        raise TLSStageError("Country FQDN no longer matches the VPS IP")
    secure_dir(root)
    node = root / node_id
    secure_dir(node)
    manifest = json.loads(private_file(node / "manifest.json"))
    if (manifest.get("node_id") != node_id or manifest.get("advertise_host") != host
            or manifest.get("state") != "testing"
            or manifest.get("activation_enabled") is not False
            or manifest.get("registration_enabled") is not False):
        raise TLSStageError("Only unpublished staged node may issue TLS")
    secure_dir(node / "dns-proxy")
    policy = json.loads(private_file(node / "dns-proxy" / "manifest.json"))
    if (policy.get("node_id") != node_id or policy.get("state") != "staged"
            or policy.get("personal_dns_enabled") is not False
            or policy.get("activation_enabled") is not False):
        raise TLSStageError("DNS policy is not isolated and inactive")
    return node


def run(cmd: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, timeout=timeout)


def cert_paths(host: str) -> tuple[Path, Path]:
    live = CERTBOT_ROOT / "live" / host
    return live / "fullchain.pem", live / "privkey.pem"


def trusted_live_file(path: Path, host: str) -> bytes:
    # Certbot live files are symlinks to its root-owned archive.
    archive = (CERTBOT_ROOT / "archive" / host).resolve()
    resolved = path.resolve(strict=True)
    if (path.parent != CERTBOT_ROOT / "live" / host
            or not resolved.is_relative_to(archive)
            or not resolved.is_file() or resolved.stat().st_uid != 0):
        raise TLSStageError("Certbot live certificate outside its own archive")
    content = resolved.read_bytes()
    if not 80 <= len(content) <= 50000:
        raise TLSStageError("Invalid TLS file size")
    return content


def verify_cert(host: str, *, runner=run) -> tuple[bytes, bytes, str]:
    chain_path, key_path = cert_paths(host)
    chain = trusted_live_file(chain_path, host)
    private = trusted_live_file(key_path, host)
    runner(["openssl", "x509", "-in", str(chain_path), "-noout",
            "-checkhost", host])
    runner(["openssl", "x509", "-in", str(chain_path), "-noout",
            "-checkend", str(MIN_REMAINING_SECONDS)])
    public_from_key = runner(["openssl", "pkey", "-in", str(key_path),
                              "-pubout", "-outform", "DER"]).stdout
    public_from_cert = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout", "-in", str(chain_path)],
        capture_output=True, check=True, timeout=20).stdout
    public_from_cert_der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public_from_cert, capture_output=True, check=True, timeout=20).stdout
    if (not public_from_key or not public_from_cert_der or
            not hmac.compare_digest(public_from_key, public_from_cert_der)):
        raise TLSStageError("TLS certificate and private key do not match")
    # The certificate chain must be signed by a trusted CA; openssl hostname
    # and key-match alone do NOT validate issuer trust. Certbot obtained this
    # from a pinned ACME production server, and we additionally check it.
    runner(["openssl", "verify", "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
            "-untrusted", str(chain_path), str(chain_path)])
    fingerprint = hashlib.sha256(chain).hexdigest()
    return chain, private, fingerprint


def write_private(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise TLSStageError("TLS destination symlink not permitted")
    if path.exists():
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise TLSStageError("TLS file not owned by Nodekit")
    fd, tmp = tempfile.mkstemp(prefix=".tls-stage-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def sync_tls(node: Path, host: str, *, runner=run) -> dict:
    chain, key, fingerprint = verify_cert(host, runner=runner)
    tls = node / "tls"
    if tls.is_symlink():
        raise TLSStageError("Unsafe TLS directory")
    tls.mkdir(mode=0o700, exist_ok=True)
    secure_dir(tls)
    write_private(tls / "privkey.pem", key)
    write_private(tls / "fullchain.pem", chain)
    record = {
        "schema_version": 1, "node_id": node.name, "hostname": host,
        "certificate_sha256": fingerprint,
        "state": "certificate_staged", "activation_enabled": False,
        "personal_dns_enabled": False, "published": False,
    }
    write_private(tls / "manifest.json",
                  (json.dumps(record, sort_keys=True) + "\n").encode())
    return record


def install_renewal(node: Path, host: str, ip: str) -> None:
    """Keep Nodekit's local TLS files in sync with certbot's regular renewals."""
    code = Path(__file__)
    if code.is_symlink() or not code.is_file() or code.stat().st_uid != 0:
        raise TLSStageError("Only trusted root-owned Nodekit source may install a hook")
    local_bin = Path("/opt/mnebyvpn-nodekit")
    if local_bin.is_symlink():
        raise TLSStageError("Persistent Nodekit code directory cannot be symlink")
    local_bin.mkdir(mode=0o755, exist_ok=True)
    if local_bin.stat().st_uid != 0 or local_bin.stat().st_mode & 0o022:
        raise TLSStageError("Unsafe permanent Nodekit code directory")
    persistent = local_bin / "tls_stage.py"
    if persistent.exists() or persistent.is_symlink():
        if (persistent.is_symlink() or not persistent.is_file()
                or persistent.stat().st_uid != 0 or
                persistent.read_bytes() != code.read_bytes()):
            raise TLSStageError("Persistent renewal code differs; review before overwriting")
    else:
        write_private(persistent, code.read_bytes())

    hooks = CERTBOT_ROOT / "renewal-hooks" / "deploy"
    if hooks.is_symlink():
        raise TLSStageError("Certbot deploy hook directory is symlinked")
    hooks.mkdir(mode=0o755, parents=True, exist_ok=True)
    if hooks.stat().st_uid != 0 or hooks.stat().st_mode & 0o022:
        raise TLSStageError("Unsafe certbot hook directory")
    hook_path = hooks / ("90-nodekit-" + node.name + ".sh")
    unit = "mnebyvpn-nodekit-coredns@" + node.name + ".service"
    commands = (
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "x$RENEWED_LINEAGE" != "x/etc/letsencrypt/live/' + host + '" ]; then exit 0; fi\n'
        "/usr/bin/python3 " + str(persistent) + " --node-id " + node.name
        + " --host " + host + " --expected-ipv4 " + ip + " --mode sync\n"
        "if systemctl is-active --quiet " + unit + "; then\n"
        "  systemctl try-reload-or-restart " + unit + "\n"
        "fi\n"
    )
    if hook_path.exists() or hook_path.is_symlink():
        if (hook_path.is_symlink() or not hook_path.is_file() or
                hook_path.stat().st_uid != 0 or
                hook_path.read_text() != commands):
            raise TLSStageError("Existing renewal hook differs")
    else:
        write_private(hook_path, commands.encode())
        hook_path.chmod(0o700)


def issue(host: str, *, runner=run) -> None:
    # Do NOT accept email or API credentials from untrusted CLI fields.
    # Standalone HTTP-01 uses a temporary port 80 listener only during ACME.
    runner(["certbot", "certonly", "--standalone",
            "--preferred-challenges", "http",
            "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email",
            "--key-type", "ecdsa",
            "--cert-name", host, "-d", host], timeout=180)


def run_mode(root: Path, node_id: str, host: str, ip: str, mode: str,
             *, runner=run, resolver=socket.getaddrinfo) -> dict:
    node = guarded_node(root, node_id, host, ip, resolver=resolver)
    if mode == "issue":
        if subprocess.run(
                ["systemctl", "is-active", "--quiet", "nginx.service"],
                timeout=10, capture_output=True, check=False).returncode == 0:
            raise TLSStageError("Nginx is active, cannot use standalone ACME")
        try:
            result = sync_tls(node, host, runner=runner)
            return dict(result, already_issued=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            # Only proceed to issue when the cert isn't present, NOT when an
            # existing cert has failed cryptographic validation.
            chain_path, key_path = cert_paths(host)
            if chain_path.exists() or key_path.exists() or chain_path.is_symlink():
                raise
        issue(host, runner=runner)
        result = sync_tls(node, host, runner=runner)
        install_renewal(node, host, ip)
        return result
    if mode in ("verify", "sync"):
        if mode == "verify":
            _, _, fingerprint = verify_cert(host, runner=runner)
            return {"node_id": node.name, "hostname": host,
                    "certificate_sha256": fingerprint, "certificate_valid": True}
        result = sync_tls(node, host, runner=runner)
        install_renewal(node, host, ip)
        return result
    raise TLSStageError("Unknown TLS mode")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--expected-ipv4", required=True)
    p.add_argument("--stage-root", type=Path, default=ROOT)
    p.add_argument("--mode", choices=("issue", "verify", "sync"), default="verify")
    args = p.parse_args()
    try:
        print(json.dumps(run_mode(args.stage_root, args.node_id, args.host,
                                  args.expected_ipv4, args.mode), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("nodekit_tls_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
