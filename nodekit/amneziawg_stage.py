#!/usr/bin/env python3
"""Stage a real AmneziaWG 3.1 userspace server with zero peers, without starting it.

This is NOT ordinary WireGuard. Requires independently built and pinned
amneziawg-go, awg and awg-quick from official Amnezia sources.
Activation, NAT, entitlements and client profiles are separate guarded steps.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

from install_components import node_ready, safe_dir, safe_manifest, digest
from nodekit import _promote_stage_noreplace

ROOT = Path("/var/lib/mnebyvpn-nodekit")
BIN = Path("/opt/mnebyvpn-amneziawg")
KEY = re.compile(r"[A-Za-z0-9+/]{43}=")
SHA = re.compile(r"[0-9a-f]{64}")
AWG_PORT = 51821
# Per-node address allocation will be controlled centrally before activation.
TEST_ADDRESS = "10.73.91.1/24"
REQUIRED = ("awg", "awg-quick", "amneziawg-go")


class AwgError(ValueError):
    pass


def safe_binary(path: Path, sha: str) -> None:
    if not SHA.fullmatch(sha):
        raise AwgError("Missing pinned executable SHA-256")
    if path.is_symlink() or not path.is_file():
        raise AwgError("Missing or symlinked AmneziaWG executable")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & 0o022 or not s.st_mode & stat.S_IXUSR:
        raise AwgError("Unsafe executable permissions")
    if digest(path) != sha:
        raise AwgError("AmneziaWG binary differs from pinned SHA-256")


def validate_stack(node: Path, hashes: dict[str, str]) -> None:
    safe_dir(BIN, private=False)
    if set(hashes) != set(REQUIRED):
        raise AwgError("Exactly three verified AmneziaWG artifacts required")
    for name in REQUIRED:
        safe_binary(BIN / name, hashes[name])
    components = safe_manifest(node / "components-manifest.json")
    if (components.get("node_id") != node.name or
            components.get("activation_enabled") is not False or
            components.get("registration_enabled") is not False):
        raise AwgError("Node components not staged")
    manifest = safe_manifest(node / "manifest.json")
    if manifest.get("listeners", {}).get("tunnel_udp") == AWG_PORT:
        raise AwgError("AmneziaWG port collides with internal tunnel")


def keygen(cmd: str, input_data: str | None = None, *, runner=subprocess.run) -> str:
    result = runner([str(BIN / "awg"), cmd],
                    input=input_data, text=True, capture_output=True,
                    check=True, timeout=12)
    value = result.stdout.strip()
    if not KEY.fullmatch(value) or len(base64.b64decode(value, validate=True)) != 32:
        raise AwgError("Unexpected AmneziaWG key format")
    return value


def make_config(private: str, header_key: str) -> str:
    if not KEY.fullmatch(private) or not KEY.fullmatch(header_key):
        raise AwgError("Invalid AmneziaWG keys")
    return (
        "# Nodekit AWG 3.1 TESTING. No peers; activation prohibited until E2E.\n"
        "[Interface]\n"
        f"Address = {TEST_ADDRESS}\n"
        f"ListenPort = {AWG_PORT}\n"
        "MTU = 1280\n"
        f"PrivateKey = {private}\n"
        "Jc = 0\n"
        "Jmin = 0\n"
        "Jmax = 0\n"
        "S1 = 16\n"
        "S2 = 16\n"
        "S3 = 16\n"
        "S4 = 16\n"
        "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
        f"HeaderProtectionKey = {header_key}\n"
        "RandomTrailers = on\n"
        "DisableCookies = off\n"
        "Table = off\n"
    )


def verify_existing(node: Path, hashes: dict[str, str]) -> dict:
    stage = node / "amneziawg"
    safe_dir(stage)
    manifest = safe_manifest(stage / "manifest.json")
    config = stage / "awg0.conf"
    if config.is_symlink() or not config.is_file() or config.stat().st_mode & 0o077:
        raise AwgError("Invalid existing AmneziaWG configuration")
    value = config.read_text()
    if (manifest.get("node_id") != node.name or
            manifest.get("state") != "staged" or
            manifest.get("activation_enabled") is not False or
            manifest.get("peers_enabled") is not False or
            manifest.get("port") != AWG_PORT or
            manifest.get("source_binary_sha256") != hashes or
            value.count("[Interface]") != 1 or "[Peer]" in value or
            "HeaderProtectionKey = " not in value or
            "RandomTrailers = on" not in value or
            "PrivateKey = " not in value or
            manifest.get("config_sha256") != hashlib.sha256(value.encode()).hexdigest()):
        raise AwgError("Existing AmneziaWG stage is modified or enabled")
    return dict(manifest, already_staged=True)


def stage_awg(node: Path, hashes: dict[str, str], *, runner=subprocess.run) -> dict:
    validate_stack(node, hashes)
    output = node / "amneziawg"
    if output.exists() or output.is_symlink():
        return verify_existing(node, hashes)
    private = keygen("genkey", runner=runner)
    public = keygen("pubkey", private + "\n", runner=runner)
    header_key = keygen("genkey", runner=runner)
    config = make_config(private, header_key)
    staging = Path(tempfile.mkdtemp(prefix=".awg-stage-", dir=node))
    try:
        staging.chmod(0o700)
        cfg = staging / "awg0.conf"
        cfg.write_text(config)
        cfg.chmod(0o600)
        # Parse with actual official awg-quick. No services or links created.
        runner([str(BIN / "awg-quick"), "strip", str(cfg)],
               check=True, capture_output=True, timeout=15, text=True)
        manifest = {
            "schema_version": 1, "node_id": node.name,
            "protocol": "AmneziaWG 3.1",
            "backend": "amneziawg-go",
            "state": "staged", "activation_enabled": False,
            "peers_enabled": False, "subscribers_enabled": False,
            "port": AWG_PORT, "test_address": TEST_ADDRESS,
            "server_public_key": public,
            "config_sha256": hashlib.sha256(config.encode()).hexdigest(),
            "source_binary_sha256": hashes,
            "pending": ["controller_address_allocation", "peer_grants",
                        "host_nat_and_forwarding", "external_e2e",
                        "expiry_revocation", "subscription_publication"],
        }
        m = staging / "manifest.json"
        m.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        m.chmod(0o600)
        _promote_stage_noreplace(staging, output)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--stage-root", type=Path, default=ROOT)
    parser.add_argument("--awg-sha256", required=True)
    parser.add_argument("--awg-quick-sha256", required=True)
    parser.add_argument("--amneziawg-go-sha256", required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise AwgError("Root required")
        node = node_ready(args.stage_root, args.node_id)
        hashes = {"awg": args.awg_sha256,
                  "awg-quick": args.awg_quick_sha256,
                  "amneziawg-go": args.amneziawg_go_sha256}
        print(json.dumps(stage_awg(node, hashes), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("nodekit_awg_stage_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
