#!/usr/bin/env python3
"""Install an immutable-source AWG worker release separate from RU188 /current.

No service unit, live controller sources, databases, keys, AWG peers, firewall,
approvals, subscriptions or client traffic are modified. Worker stays OFF.
Only a SHA-pinned, complete five-module TypeScript source graph is staged.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

import fi_awg_worker_source_stage as trust

# Versioned and never pointed at the live /opt/mnebyvpn-controller/current tree.
RELEASES = Path("/opt/mnebyvpn-controller/awg-worker-releases")
RELEASE = RELEASES / trust.PINNED_COMMIT
MARKER = "awg-source-manifest.json"
IMPORT = re.compile(rb"\bfrom\s+['\"]([^'\"]+)['\"]")


def require_source_closure(blobs: dict[str, bytes]) -> None:
    """Reject incomplete imports instead of discovering missing code on boot."""
    allowed = set(blobs)
    for rel, body in blobs.items():
        for source in IMPORT.findall(body):
            try:
                name = source.decode("ascii")
            except UnicodeError:
                trust.stop("invalid_worker_import")
            if name.startswith("node:") or name == "pg":
                continue
            if not name.startswith("."):
                trust.stop("unapproved_worker_import")
            # Every relative import is a pinned TypeScript source in this release.
            joined = PurePosixPath(rel).parent.joinpath(name)
            parts = []
            for part in joined.parts:
                if part == "..":
                    if not parts:
                        trust.stop("worker_import_outside_release")
                    parts.pop()
                elif part not in (".", ""):
                    parts.append(part)
            if "/".join(parts) not in allowed:
                trust.stop("missing_relative_worker_import")


def verify_ancestry() -> None:
    trust.safe_directory(Path("/opt/mnebyvpn-controller"))
    if RELEASES.exists() or RELEASES.is_symlink():
        trust.safe_directory(RELEASES)
    if RELEASE.exists() or RELEASE.is_symlink():
        trust.safe_directory(RELEASE)


def file_matches(path: Path, data: bytes) -> bool:
    if path.exists() or path.is_symlink():
        if trust.read_file(path, max(65536, len(data) + 1)) != data:
            trust.stop("existing_isolated_release_mismatch")
        return True
    return False


def write_new(path: Path, payload: bytes) -> None:
    # O_EXCL and NOFOLLOW: no silent replacement during an interrupted rerun.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        trust.stop("concurrent_isolated_release_write")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def stage_release(source: Path) -> tuple[int, int]:
    # The *existing*, reviewed trust checks enforce RU188, root, DB release
    # false, service inactive, approval absent, and source hashes.
    trust.require_safe_dormant()
    blobs = trust.approved_sources(source)
    require_source_closure(blobs)
    manifest = trust.read_file(source / "manifest.json", 4096)
    verify_ancestry()

    lock = trust.ROOT / "awg-worker-source-stage.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_nlink != 1):
            trust.stop("unsafe_isolated_release_lock")
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        trust.require_safe_dormant()
        verify_ancestry()
        # Preflight all existing bytes before any missing path is created.
        matched = 0
        pending = []
        for rel, content in sorted(blobs.items()):
            target = RELEASE / rel
            if target.exists() or target.is_symlink():
                if file_matches(target, content):
                    matched += 1
            else:
                pending.append((target, content))
        marker = RELEASE / MARKER
        if marker.exists() or marker.is_symlink():
            if not file_matches(marker, manifest):
                trust.stop("existing_isolated_manifest_mismatch")
            # A published manifest must never accompany a partial release.
            if pending:
                trust.stop("partial_isolated_release_with_manifest")
        if not (RELEASES.exists() or RELEASES.is_symlink()):
            trust.make_directory(RELEASES)
        if not (RELEASE.exists() or RELEASE.is_symlink()):
            trust.make_directory(RELEASE)
        written = 0
        for dest, data in pending:
            folder = RELEASE
            for component in dest.parent.relative_to(RELEASE).parts:
                folder = folder / component
                if not (folder.exists() or folder.is_symlink()):
                    trust.make_directory(folder)
                else:
                    trust.safe_directory(folder)
            write_new(dest, data)
            written += 1
        # Verify complete exact graph before publishing a source-manifest.
        for rel, content in blobs.items():
            if not file_matches(RELEASE / rel, content):
                trust.stop("incomplete_isolated_source_release")
        if not marker.exists():
            write_new(marker, manifest)
        elif not file_matches(marker, manifest):
            trust.stop("isolated_manifest_changed")
        # No node_modules symlink or runtime is attached; that is a separate
        # reviewed preparation stage. This is NOT an executable worker yet.
        return written, matched
    finally:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    if not args.stage.is_absolute() or not re.fullmatch(
            r"/run/fi-awg-row-lock\.[A-Za-z0-9]{8}", str(args.stage)):
        trust.stop("unapproved_isolated_stage_path")
    created, matched = stage_release(args.stage)
    print(f"FI_AWG_ISOLATED_SOURCE=STAGED;NEW={created};MATCHED={matched};"
          f"MODULES={len(trust.FILES)};WORKER_STARTED=false;"
          "CUSTOMER_RELEASE=false;RUNTIME_ATTACHED=false")


if __name__ == "__main__":
    try:
        main()
    except (trust.StageBlocked, OSError, ValueError, TypeError, KeyError,
            UnicodeError):
        raise SystemExit(2)
