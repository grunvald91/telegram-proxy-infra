#!/usr/bin/env python3
"""Generate a unique new-VPS Ed25519 identity using installed OpenSSL.

No Node.js runtime is required on a fresh Debian/Ubuntu VPS. This produces
PKCS8 DER + SPKI DER compatible with nodekit/sign-enrollment.mjs and the
central PostgreSQL registration contract. No deployment or network changes.
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
import subprocess
import sys


class IdentityError(ValueError):
    pass


def private_directory(path: Path, *, require_root: bool) -> None:
    if path.is_symlink() or not path.is_dir():
        raise IdentityError("Unsafe identity directory")
    st = path.stat()
    if st.st_mode & 0o077 or (require_root and st.st_uid != 0):
        raise IdentityError("Identity directory must be private and owned by root")


def create_identity(stage_root: Path, node_id: str, *, require_root: bool = True) -> dict:
    if not isinstance(node_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,39}", node_id) or node_id.endswith("-"):
        raise IdentityError("Invalid node_id")
    if require_root and os.geteuid() != 0:
        raise IdentityError("Run as root on the new VPS")
    private_directory(stage_root, require_root=require_root)
    node_dir = stage_root / node_id
    private_directory(node_dir, require_root=require_root)
    manifest_file = node_dir / "manifest.json"
    if manifest_file.is_symlink() or not manifest_file.is_file() or manifest_file.stat().st_size > 4096:
        raise IdentityError("Invalid node manifest")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if (manifest.get("node_id") != node_id or manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            not isinstance(manifest.get("advertise_host"), str) or
            "." not in manifest["advertise_host"]):
        raise IdentityError("Only staged, unpublished nodes may get an identity")
    executable = shutil.which("openssl")
    if executable is None:
        raise IdentityError("OpenSSL is required on the new VPS")
    identity = node_dir / "identity"
    # Creating this directory is the only way to claim identity creation.
    # Never overwrite, rotate, reuse or copy keys from other nodes.
    identity.mkdir(mode=0o700)
    try:
        private_dir = identity / "node-private.pk8"
        public_dir = identity / "node-public.spki"
        old_umask = os.umask(0o077)
        try:
            subprocess.run([executable, "genpkey", "-algorithm", "ED25519", "-outform", "DER",
                            "-out", str(private_dir)],
                           check=True, timeout=10, capture_output=True)
            subprocess.run([executable, "pkey", "-inform", "DER", "-in", str(private_dir),
                            "-pubout", "-outform", "DER", "-out", str(public_dir)],
                           check=True, timeout=10, capture_output=True)
        finally:
            os.umask(old_umask)
        if private_dir.is_symlink() or public_dir.is_symlink():
            raise IdentityError("Symlink detected during identity generation")
        private_dir.chmod(0o600)
        public_dir.chmod(0o600)
        pub = public_dir.read_bytes()
        private_len = private_dir.stat().st_size
        if len(pub) != 44 or not 40 <= private_len <= 256:
            raise IdentityError("Invalid Ed25519 key material")
        return {
            "node_id": node_id,
            "identity_public_spki": base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii"),
            "identity_public_sha256": hashlib.sha256(pub).hexdigest(),
            "enabled": False,
            "enrolled": False,
        }
    except Exception:
        # A failed first-time key creation should not leave partial identity.
        # Never delete an existing identity because mkdir would have failed.
        shutil.rmtree(identity)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--stage-root", type=Path,
                        default=Path("/var/lib/mnebyvpn-nodekit"))
    args = parser.parse_args()
    try:
        result = create_identity(args.stage_root, args.node_id)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IdentityError, OSError, subprocess.SubprocessError, ValueError) as exc:
        # Never leak OpenSSL output or private-key path into Action logs.
        print("node_identity_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
