#!/usr/bin/env python3
"""Stage a separate, inactive Xray REALITY instance for a NEW Nodekit VPS.

Requires a locally installed root-owned Xray binary with an externally verified
expected SHA-256. This is NOT a downloader, daemon or subscriber provisioner.
It does not activate, publish, touch nginx/WireGuard/firewall, or edit /etc.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable

PREFIX_X25519_PKCS8 = bytes.fromhex("302e020100300506032b656e04220420")
PREFIX_X25519_SPKI = bytes.fromhex("302a300506032b656e032100")
PREFIX_ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
HEX = re.compile(r"[a-f0-9]{64}")
KEY = re.compile(r"[A-Za-z0-9_-]{43}")
NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}")


class VpnStageError(ValueError):
    pass


def _private_dir(path: Path, require_root: bool) -> None:
    if path.is_symlink() or not path.is_dir():
        raise VpnStageError("Required Nodekit stage directory missing")
    st = path.stat()
    if st.st_mode & 0o077 or (require_root and st.st_uid != 0):
        raise VpnStageError("Nodekit directory has unsafe permissions")


def _safe_file(path: Path, require_root: bool, max_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise VpnStageError("Nodekit source file is not a safe regular file")
    if require_root and path.stat().st_uid != 0:
        raise VpnStageError("Nodekit file must be owned by root")
    return path.read_bytes()


def _hash_binary(path: Path, require_root: bool) -> str:
    if path.is_symlink() or not path.is_file():
        raise VpnStageError("Xray binary must be a regular file (not a symlink)")
    st = path.stat()
    if ((require_root and st.st_uid != 0) or st.st_mode & 0o022 or
            not st.st_mode & stat.S_IXUSR or st.st_size < 10_000 or
            st.st_size > 150 * 1024 * 1024):
        raise VpnStageError("Xray binary ownership, mode, size or executable bit invalid")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(args: list[str], *, input: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input, capture_output=True, check=True, timeout=12)


def derive_reality_public(private: str, openssl: Path,
                          runner: Callable[..., subprocess.CompletedProcess]) -> str:
    if not KEY.fullmatch(private):
        raise VpnStageError("Xray returned an invalid REALITY private key")
    try:
        raw = base64.urlsafe_b64decode(private + "==")
    except (ValueError, base64.binascii.Error) as exc:
        raise VpnStageError("Invalid X25519 private key encoding") from exc
    if len(raw) != 32:
        raise VpnStageError("Invalid X25519 private key size")
    public_der = runner(
        [str(openssl), "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=PREFIX_X25519_PKCS8 + raw,
    ).stdout
    if (not public_der.startswith(PREFIX_X25519_SPKI) or
            len(public_der) != len(PREFIX_X25519_SPKI) + 32):
        raise VpnStageError("OpenSSL X25519 public key derivation invalid")
    return base64.urlsafe_b64encode(public_der[len(PREFIX_X25519_SPKI):]).rstrip(b"=").decode()


def stage_vpn(stage_root: Path, node_id: str, xray: Path,
              expected_sha256: str, *, require_root: bool = True,
              runner: Callable[..., subprocess.CompletedProcess] = _run,
              openssl: Path | None = None) -> dict[str, Any]:
    if (not isinstance(node_id, str) or not NODE.fullmatch(node_id) or
            node_id.endswith("-") or
            not isinstance(expected_sha256, str) or not HEX.fullmatch(expected_sha256)):
        raise VpnStageError("Invalid node ID or Xray digest")
    if require_root and os.geteuid() != 0:
        raise VpnStageError("Root required to prepare new VPN node")
    _private_dir(stage_root, require_root)
    node_dir = stage_root / node_id
    _private_dir(node_dir, require_root)
    manifest = json.loads(_safe_file(node_dir / "manifest.json", require_root, 4096))
    if (manifest.get("node_id") != node_id or manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            manifest.get("activation_enabled") is not False or
            "vpn" not in manifest.get("roles", []) or
            not isinstance(manifest.get("advertise_host"), str) or
            not manifest["advertise_host"].count(".") >= 1):
        raise VpnStageError("Only an unpublished staged VPN node can be prepared")
    _private_dir(node_dir / "identity", require_root)
    identity_pub = _safe_file(node_dir / "identity" / "node-public.spki",
                              require_root, 44)
    if len(identity_pub) != 44 or not identity_pub.startswith(PREFIX_ED25519_SPKI):
        raise VpnStageError("Valid unique Ed25519 node identity is required")
    current_hash = _hash_binary(xray, require_root)
    if current_hash != expected_sha256:
        raise VpnStageError("Locally installed Xray hash does not match expected version")
    openssl_path = openssl or Path(shutil.which("openssl") or "/nonexistent")
    if openssl_path.is_symlink() or not openssl_path.is_file():
        raise VpnStageError("OpenSSL must be installed locally")
    published_port = manifest.get("listeners", {}).get("vpn_tcp")
    if type(published_port) is not int or not 1024 <= published_port <= 65535:
        raise VpnStageError("Invalid unprivileged VPN port")
    vpn_dir = node_dir / "vpn"
    if vpn_dir.exists() or vpn_dir.is_symlink():
        raise VpnStageError("Never overwrite an existing VPN staging identity")
    stage = Path(tempfile.mkdtemp(prefix=".vpn-stage-", dir=node_dir))
    try:
        stage.chmod(0o700)
        keyout = runner([str(xray), "x25519"]).stdout
        if isinstance(keyout, bytes):
            keyout = keyout.decode("ascii")
        match = re.search(r"(?im)^\s*private\s*key\s*:\s*(\S+)\s*$", keyout)
        if not match:
            raise VpnStageError("Unsupported Xray key generation format")
        private = match.group(1)
        public = derive_reality_public(private, openssl_path, runner)
        sid = secrets.token_hex(8)
        reality_name = "www.cloudflare.com"
        template = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": f"nodekit-{node_id}-reality",
                "listen": "0.0.0.0", "port": published_port,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp", "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": reality_name + ":443",
                        "xver": 0,
                        "serverNames": [reality_name],
                        "privateKey": private,
                        "shortIds": [sid],
                    }
                },
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        }
        config = stage / "xray-config.json"
        config.write_text(json.dumps(template, ensure_ascii=False, separators=(",", ":")) + "\n")
        config.chmod(0o600)
        validation = runner([str(xray), "run", "-test", "-config", str(config)])
        if validation.returncode != 0:
            raise VpnStageError("Xray config validation failed")
        report = {
            "schema_version": 1, "node_id": node_id,
            "advertise_host": manifest["advertise_host"],
            "xray_sha256": current_hash,
            "vpn_port": published_port, "reality_sni": reality_name,
            "reality_public_key": public, "reality_short_id": sid,
            "identity_public_sha256": hashlib.sha256(identity_pub).hexdigest(),
            "state": "staged",
            "vpn_users_enabled": False,
            "activation_enabled": False,
            "controller_enrolled": False,
            "independent_e2e_verified": False,
            "pending": [
                "node_access_supervisor", "node_expiry_and_revoke_enforcement",
                "operator_enrollment", "independent_e2e", "subscriber_grants",
            ],
        }
        pub = stage / "vpn-stage-manifest.json"
        pub.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        pub.chmod(0o600)
        if vpn_dir.exists() or vpn_dir.is_symlink():
            raise VpnStageError('VPN state appeared during staging: refuse overwrite')
        stage.rename(vpn_dir)
        return report
    except Exception:
        shutil.rmtree(stage)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--xray-sha256", required=True)
    parser.add_argument("--stage-root", type=Path,
                        default=Path("/var/lib/mnebyvpn-nodekit"))
    args = parser.parse_args()
    try:
        result = stage_vpn(args.stage_root, args.node_id, args.xray, args.xray_sha256)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError) as exc:
        # Do not print Xray private key, config, credential or stdout/stderr.
        print("node_vpn_stage_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
