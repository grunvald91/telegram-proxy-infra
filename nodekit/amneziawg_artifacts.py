#!/usr/bin/env python3
"""Install verified AmneziaWG build artifacts on isolated NEW node.

Artifacts are built from pinned official GitHub commits by controlled Actions.
Strictly no overwriting existing code, no service startup or firewall changes.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from install_components import digest, node_ready, safe_dir

DEST = Path("/opt/mnebyvpn-amneziawg")
SHA = re.compile(r"[a-f0-9]{64}")
NAMES = ("awg", "awg-quick", "amneziawg-go")
SOURCE_COMMITS = {
    "tools": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
    "userspace": "08fe3d33bbb116be09a6183d02609311b8b0c9e8",
}


class ArtifactError(ValueError):
    pass


def stage_artifacts(node: Path, bundle: Path, hashes: dict[str, str]) -> dict:
    if set(hashes) != set(NAMES) or not all(SHA.fullmatch(v) for v in hashes.values()):
        raise ArtifactError("Pinned SHA-256 required for all AmneziaWG binaries")
    safe_dir(bundle)
    if DEST.is_symlink():
        raise ArtifactError("Binary directory may not be a symlink")
    if not DEST.exists():
        DEST.mkdir(mode=0o755)
    safe_dir(DEST, private=False)
    for name in NAMES:
        path = bundle / name
        if path.is_symlink() or not path.is_file():
            raise ArtifactError("Missing verified artifact")
        s = path.stat()
        if s.st_uid != 0 or s.st_mode & 0o022 or not 100 <= s.st_size <= 120_000_000:
            raise ArtifactError("Unsafe artifact ownership/size")
        if digest(path) != hashes[name]:
            raise ArtifactError("Artifact SHA-256 mismatch")
    for name in NAMES:
        target = DEST / name
        if target.is_symlink():
            raise ArtifactError("Installed artifact symlink forbidden")
        if target.exists():
            s = target.stat()
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
                    not s.st_mode & stat.S_IXUSR or digest(target) != hashes[name]):
                raise ArtifactError("Installed artifact differs; refuse overwrite")
            continue
        fd, pending = tempfile.mkstemp(prefix=".nodekit-awg-", dir=DEST)
        try:
            os.fchmod(fd, 0o755)
            with os.fdopen(fd, "wb") as out, (bundle / name).open("rb") as src:
                while chunk := src.read(1048576):
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            if digest(Path(pending)) != hashes[name]:
                raise ArtifactError("Copied artifact checksum mismatch")
            os.link(pending, target, follow_symlinks=False)
        finally:
            Path(pending).unlink(missing_ok=True)
    return {"node_id": node.name, "source_commits": SOURCE_COMMITS,
            "hashes": hashes, "artifacts_installed": True, "activation_enabled": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--stage-root", type=Path, default=Path("/var/lib/mnebyvpn-nodekit"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--awg-sha256", required=True)
    parser.add_argument("--awg-quick-sha256", required=True)
    parser.add_argument("--amneziawg-go-sha256", required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ArtifactError("Root required")
        node = node_ready(args.stage_root, args.node_id)
        hashes = {"awg": args.awg_sha256,
                  "awg-quick": args.awg_quick_sha256,
                  "amneziawg-go": args.amneziawg_go_sha256}
        print(json.dumps(stage_artifacts(node, args.bundle, hashes), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print("nodekit_awg_artifacts_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
