#!/usr/bin/env python3
"""Stage reviewed FI217 AWG controller candidate as immutable RU188 source only.

No migration of /current, no change to the effective systemd unit, no workers
started, no PostgreSQL writes, no entitlements or subscriptions published.
The old c73ddaa release remains the effective, disabled worker until a
separately reviewed and verified cutover.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_source_stage as isolated
import fi_awg_worker_isolated_systemd_stage as systemd

CANDIDATE_COMMIT = "6743387075102698ab23ec06de364d0d8efd1dca"
OLD_COMMIT = "c73ddaa237543d91dc81fb09eb3f371389dc618d"
RELEASES = Path("/opt/mnebyvpn-controller/awg-worker-releases")
CANDIDATE = RELEASES / CANDIDATE_COMMIT
MARKER = "awg-source-manifest.json"
STAGING = re.compile(r"/run/fi-awg-worker-upgrade\.[A-Za-z0-9]{8}\Z")


SIDE_EFFECT_IMPORT = re.compile(rb"\bimport\s*['\"]([^'\"]+)['\"]")
DYNAMIC_IMPORT = re.compile(rb"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
ANY_DYNAMIC_IMPORT = re.compile(rb"\bimport\s*\(")


def verify_nonstandard_imports(blobs: dict[str, bytes]) -> None:
    """Reject side-effect and computed imports omitted by legacy closure check."""
    allowed = set(blobs)
    for relative, body in blobs.items():
        dynamic = DYNAMIC_IMPORT.findall(body)
        if len(ANY_DYNAMIC_IMPORT.findall(body)) != len(dynamic):
            trust.stop("candidate_computed_dynamic_import")
        for source in SIDE_EFFECT_IMPORT.findall(body) + dynamic:
            try:
                name = source.decode("ascii")
            except UnicodeError:
                trust.stop("candidate_non_ascii_import")
            if name.startswith("node:") or name == "pg":
                continue
            if not name.startswith("."):
                trust.stop("candidate_unapproved_import")
            path = PurePosixPath(relative).parent.joinpath(name)
            parts = []
            for component in path.parts:
                if component == "..":
                    if not parts:
                        trust.stop("candidate_import_outside_release")
                    parts.pop()
                elif component not in (".", ""):
                    parts.append(component)
            if "/".join(parts) not in allowed:
                trust.stop("candidate_import_module_missing")


# Independently reviewed Git object IDs from the immutable Mnebyvpn commit.
# The checked-in source manifest additionally uses SHA-256 to catch corruption,
# but it must not itself decide which code is approved.
PINNED_SOURCE_BLOBS = {
    "awg-controller-delivery-worker.ts": "dbbacac3798bd13cb4f4f624936e7afe67ce3cf3",
    "awg-trusted-ssh-delivery.ts": "516706e898f6e59599172ce3c65d9f2295a4876e",
    "awg-offline-maintenance.ts": "e8829944ca4d27e1d8b8679efa681f6bb3abe373",
    "awg-controller-grants.ts": "9b37bb3e9528e6bab4144d36b4558ca61d544b41",
    "awg-controller-outbox.ts": "0b1c1f0906a0a11be8a1c466fa5eb173bd39906b",
}


def verify_pinned_source_blob(name: str, body: bytes) -> None:
    """Check reviewed Git blob identity, independent of supplied manifest."""
    expected = PINNED_SOURCE_BLOBS.get(name)
    if (set(PINNED_SOURCE_BLOBS) != set(trust.FILES) or
            not isinstance(expected, str) or
            not re.fullmatch(r"[a-f0-9]{40}", expected) or
            not isinstance(body, bytes)):
        trust.stop("candidate_source_pin_table_invalid")
    actual = hashlib.sha1(
        b"blob " + str(len(body)).encode("ascii") + b"\0" + body
    ).hexdigest()
    if actual != expected:
        trust.stop("candidate_source_not_independently_pinned")


def candidate_blobs(stage: Path) -> tuple[bytes, dict[str, bytes]]:
    trust.safe_directory(stage)
    raw = trust.read_file(stage / "manifest.json", 4096)
    try:
        manifest = json.loads(raw)
    except (UnicodeError, ValueError):
        trust.stop("candidate_manifest_invalid")
    if (not isinstance(manifest, dict) or set(manifest) != {"commit", "files"} or
            manifest["commit"] != CANDIDATE_COMMIT or
            not isinstance(manifest["files"], dict) or
            set(manifest["files"]) != set(trust.FILES)):
        trust.stop("candidate_manifest_not_pinned")
    blobs: dict[str, bytes] = {}
    for name, rel in trust.FILES.items():
        sha = manifest["files"][name]
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
            trust.stop("candidate_hash_invalid")
        body = trust.read_file(stage / name)
        verify_pinned_source_blob(name, body)
        if hashlib.sha256(body).hexdigest() != sha or not body.endswith(b"\n"):
            trust.stop("candidate_source_digest_mismatch")
        blobs[rel] = body
    isolated.require_source_closure(blobs)
    verify_nonstandard_imports(blobs)
    return raw, blobs


def guard() -> None:
    # The old systemd worker must remain disabled and still point at the exact
    # independently verified old release. Never silently use /current.
    if trust.PINNED_COMMIT != OLD_COMMIT:
        trust.stop("legacy_worker_pin_changed")
    systemd.dormant_and_disabled()
    systemd.approved_base_unit()
    systemd.exact_effective_unit()
    systemd.source_verified()
    for path in (RELEASES, CANDIDATE):
        if path.exists() or path.is_symlink():
            trust.safe_directory(path)


def verified_existing(path: Path, body: bytes) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    if trust.read_file(path, 65536) != body:
        trust.stop("candidate_existing_source_drift")
    return True


def install(stage: Path) -> tuple[int, int]:
    # All candidate sources and the still-dormant old worker must be verified
    # before ANY file is created on RU188.
    manifest, blobs = candidate_blobs(stage)
    guard()
    lock = trust.ROOT / "awg-worker-source-stage.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o077 or st.st_nlink != 1):
            trust.stop("candidate_stage_lock_unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        guard()
        missing = []
        matched = 0
        for path, blob in sorted(blobs.items()):
            destination = CANDIDATE / path
            if verified_existing(destination, blob):
                matched += 1
            else:
                missing.append((destination, blob))
        marker = CANDIDATE / MARKER
        marker_exists = verified_existing(marker, manifest)
        if marker_exists and missing:
            trust.stop("candidate_published_manifest_incomplete")
        if not RELEASES.exists():
            trust.make_directory(RELEASES)
        if not CANDIDATE.exists():
            trust.make_directory(CANDIDATE)
        for destination, blob in missing:
            parent = CANDIDATE
            for component in destination.parent.relative_to(CANDIDATE).parts:
                parent /= component
                trust.make_directory(parent)
            isolated.write_new(destination, blob)
        for path, blob in blobs.items():
            if not verified_existing(CANDIDATE / path, blob):
                trust.stop("candidate_install_incomplete")
        if not marker_exists:
            isolated.write_new(marker, manifest)
        # Sync the published marker's directory before reporting STAGED.
        root_fd = os.open(CANDIDATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        guard()
        return len(missing), matched
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    if not args.stage.is_absolute() or not STAGING.fullmatch(str(args.stage)):
        trust.stop("candidate_unapproved_staging_path")
    new, matched = install(args.stage)
    print(f"FI_AWG_WORKER_CANDIDATE=STAGED;COMMIT={CANDIDATE_COMMIT};"
          f"NEW={new};MATCHED={matched};TOTAL={len(trust.FILES)};"
          "EFFECTIVE_RELEASE=LEGACY_DISABLED;CUSTOMER_RELEASE=false")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (trust.StageBlocked, OSError, ValueError, TypeError, KeyError,
            UnicodeError):
        raise SystemExit(2)
