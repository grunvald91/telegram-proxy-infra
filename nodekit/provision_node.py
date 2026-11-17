#!/usr/bin/env python3
"""Idempotent NEW-node provisioning: stage -> identity -> components -> VPN.

Never activates network services, changes firewall, creates VPN subscribers,
or registers a node in production. Fail closed on conflicting staged state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from nodekit import load_spec, validate_spec
from install_components import node_ready, safe_dir, safe_manifest, digest

ROOT = Path("/var/lib/mnebyvpn-nodekit")


class ProvisionError(ValueError):
    pass


def spec_digest(spec: dict) -> str:
    encoded = json.dumps(spec, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_node_manifest(node: Path, spec: dict) -> None:
    manifest = safe_manifest(node / "manifest.json")
    if (manifest.get("node_id") != spec["node_id"] or
            manifest.get("spec_sha256") != spec_digest(spec) or
            manifest.get("advertise_host") != spec["advertise_host"] or
            manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            manifest.get("activation_enabled") is not False):
        raise ProvisionError("Existing node is not the identical unpublished spec")


def verify_identity(node: Path) -> None:
    identity = node / "identity"
    safe_dir(identity)
    for name in ("node-private.pk8", "node-public.spki"):
        path = identity / name
        if path.is_symlink() or not path.is_file():
            raise ProvisionError("Incomplete or symlinked identity")
        s = path.stat()
        if s.st_uid != 0 or s.st_mode & 0o077 or not 32 <= s.st_size <= 256:
            raise ProvisionError("Unsafe identity")
    pub = (identity / "node-public.spki").read_bytes()
    if len(pub) != 44 or not pub.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ProvisionError("Unexpected node Ed25519 public key")


def verify_vpn(node: Path, xray_hash: str) -> None:
    vpn = node / "vpn"
    safe_dir(vpn)
    staged = safe_manifest(vpn / "vpn-stage-manifest.json")
    config = safe_manifest(vpn / "xray-config.json")
    inbounds = config.get("inbounds")
    if (staged.get("node_id") != node.name or
            staged.get("xray_sha256") != xray_hash or
            staged.get("state") != "staged" or
            staged.get("activation_enabled") is not False or
            staged.get("vpn_users_enabled") is not False or
            not isinstance(inbounds, list) or len(inbounds) != 1 or
            not isinstance(inbounds[0], dict) or
            not isinstance(inbounds[0].get("settings"), dict) or
            inbounds[0]["settings"].get("clients") != []):
        raise ProvisionError("Existing VPN stage is not an empty testing instance")


def execute(script: Path, *args: str) -> None:
    if script.is_symlink() or not script.is_file():
        raise ProvisionError("Missing trusted Nodekit script")
    subprocess.run([sys.executable, str(script), *args], check=True, timeout=780)


def prepare(spec_path: Path, source: Path, root: Path = ROOT) -> dict:
    if os.geteuid() != 0:
        raise ProvisionError("Root required")
    spec = validate_spec(load_spec(spec_path))
    node_id = spec["node_id"]
    node = root / node_id
    # The stage step itself validates port availability and supported OS.
    if not node.exists() and not node.is_symlink():
        execute(source / "nodekit.py", "stage", "--spec", str(spec_path),
                "--stage-root", str(root))
    else:
        safe_dir(root)
        safe_dir(node)
    verify_node_manifest(node, spec)

    identity = node / "identity"
    if not identity.exists() and not identity.is_symlink():
        execute(source / "identity.py", "--node-id", node_id,
                "--stage-root", str(root))
    verify_identity(node)

    # Recheck the immutable new-node manifest/identity and install real
    # signed-distro packages + official SHA256-verified release binaries.
    node_ready(root, node_id)
    execute(source / "install_components.py", "--node-id", node_id,
            "--stage-root", str(root), "--mode", "install")

    comp = safe_manifest(node / "components-manifest.json")
    binaries = comp.get("binaries", {})
    if (comp.get("node_id") != node_id or
            comp.get("activation_enabled") is not False or
            not isinstance(binaries, dict) or
            not isinstance(binaries.get("xray"), dict)):
        raise ProvisionError("Invalid installed component record")
    xray = Path("/opt/xray/xray")
    sha = binaries["xray"].get("sha256")
    if not isinstance(sha, str) or len(sha) != 64 or digest(xray) != sha:
        raise ProvisionError("Installed Xray integrity failure")

    vpn = node / "vpn"
    if not vpn.exists() and not vpn.is_symlink():
        execute(source / "vpn_stage.py", "--node-id", node_id,
                "--stage-root", str(root), "--xray", str(xray),
                "--xray-sha256", sha)
    verify_vpn(node, sha)
    return {"node_id": node_id, "state": "vpn_staged",
            "identity_created": True, "components_installed": True,
            "vpn_users_enabled": False, "activation_enabled": False,
            "published": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--stage-root", type=Path, default=ROOT)
    options = parser.parse_args()
    try:
        if options.source_dir.is_symlink() or not options.source_dir.is_dir():
            raise ProvisionError("Missing or symlinked source directory")
        print(json.dumps(prepare(options.spec, options.source_dir, options.stage_root),
                         sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, TypeError) as err:
        print("nodekit_prepare_all_error=" + type(err).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
