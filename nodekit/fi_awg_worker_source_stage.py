#!/usr/bin/env python3
"""RU188-only, guarded idempotent install of pinned AWG worker source (NO activation).

Only creates missing, immutable-review-matched TypeScript source files under
the already existing controller /opt/.../current tree. It does not restart or
enable any process, change PostgreSQL, issue leases, or publish subscribers.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys

RU = "188.120.254.223"
FI = "fi-test-01"
PINNED_COMMIT = "c73ddaa237543d91dc81fb09eb3f371389dc618d"
ROOT = Path("/root/mnebyvpn-controller")
CURRENT = Path("/opt/mnebyvpn-controller/current")
FILES = {
    "awg-controller-delivery-worker.ts": "apps/service/src/awg-controller-delivery-worker.ts",
    "awg-trusted-ssh-delivery.ts": "packages/provisioning/src/awg-trusted-ssh-delivery.ts",
    "awg-offline-maintenance.ts": "packages/provisioning/src/awg-offline-maintenance.ts",
    "awg-controller-grants.ts": "packages/provisioning/src/awg-controller-grants.ts",
    "awg-controller-outbox.ts": "packages/provisioning/src/awg-controller-outbox.ts",
}


class StageBlocked(ValueError):
    pass


def stop(label: str) -> None:
    print("FI_AWG_WORKER_SOURCE_BLOCKED=" + label, file=sys.stderr)
    raise StageBlocked(label)


def is_ru188() -> bool:
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                data = fcntl.ioctl(sock.fileno(), 0x8915,
                                   struct.pack("256s", name.encode()))
                if socket.inet_ntoa(data[20:24]) == RU:
                    return True
            except OSError:
                pass
    return False


def safe_directory(folder: Path) -> None:
    for path in (folder, *folder.parents):
        try:
            s = path.lstat()
        except OSError:
            stop("missing_protected_directory")
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            stop("untrusted_directory_or_symlink")


def current_directory() -> Path:
    """Resolve only a root-owned current -> controller-local release pointer."""
    base = Path("/opt/mnebyvpn-controller")
    safe_directory(base)
    try:
        meta = CURRENT.lstat()
    except OSError:
        stop("controller_current_missing")
    if stat.S_ISLNK(meta.st_mode):
        if meta.st_uid != 0:
            stop("controller_current_link_owner_untrusted")
        try:
            target = CURRENT.resolve(strict=True)
        except (OSError, RuntimeError):
            stop("controller_current_link_broken")
        if target == base or not target.is_relative_to(base):
            stop("controller_current_link_outside_trusted_tree")
        safe_directory(target)
        return target
    safe_directory(CURRENT)
    return CURRENT


def read_file(path: Path, limit: int = 65536) -> bytes:
    safe_directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        stop("source_file_missing_or_symlink")
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
                s.st_mode & 0o022 or s.st_nlink != 1 or
                not 1 <= s.st_size <= limit):
            stop("source_file_unsafe")
        data = os.read(fd, limit + 1)
        if len(data) != s.st_size:
            stop("source_file_changed")
        return data
    finally:
        os.close(fd)


def require_safe_dormant() -> None:
    if not is_ru188():
        stop("not_existing_ru188_root")
    safe_directory(ROOT)
    current = current_directory()
    if (ROOT / "approvals/awg-delivery.enable").exists() or (
            ROOT / "approvals/awg-delivery.enable").is_symlink():
        stop("worker_approval_already_present")
    try:
        service = subprocess.run(
            ["/usr/bin/systemctl", "show", "-p", "ActiveState", "--value",
             "mnebyvpn-awg-delivery.service"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        stop("worker_state_unavailable")
    if service.returncode or service.stdout.strip() != "inactive":
        stop("worker_is_not_inactive")
    # This stages ONLY source for the already reviewed unpublished FI node.
    try:
        db = subprocess.run(
            ["/usr/bin/docker", "exec", "mnebyvpn-stage-postgres", "psql",
             "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
             "-U", "mnebyvpn_stage", "-d", "mnebyvpn_stage",
             "-c", "SELECT (SELECT status FROM public.vpn_node_enrollment_inventory "
                   "WHERE node_id='fi-test-01'),"
                   "(SELECT enabled::text FROM public.vpn_release_flags "
                   "WHERE feature='vpn_awg_clients');"],
            capture_output=True, text=True, timeout=16, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        stop("canonical_database_unavailable")
    if db.returncode or db.stdout.strip() != "enrolled|false":
        stop("not_unpublished_enrolled_fi")
    if not (current / "bin/node").is_file() or not (
            current / "node_modules/pg/lib/index.js").is_file():
        stop("canonical_node_runtime_missing")


def approved_sources(stage: Path) -> dict[str, bytes]:
    safe_directory(stage)
    raw = read_file(stage / "manifest.json", 4096)
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        stop("invalid_source_manifest")
    if (not isinstance(manifest, dict) or set(manifest) !=
            {"commit", "files"} or manifest["commit"] != PINNED_COMMIT or
            not isinstance(manifest["files"], dict) or
            set(manifest["files"]) != set(FILES)):
        stop("unapproved_source_manifest")
    blobs = {}
    for name, relpath in FILES.items():
        digest = manifest["files"][name]
        if not isinstance(digest, str) or not re.fullmatch("[a-f0-9]{64}", digest):
            stop("invalid_pinned_source_hash")
        data = read_file(stage / name)
        if hashlib.sha256(data).hexdigest() != digest:
            stop("pinned_source_hash_mismatch")
        if (not data.endswith(b"\n") or b"\0" in data or not any(
                marker in data for marker in
                (b"from 'node:", b"import type", b"from './", b"from '../../../"))):
            stop("unrecognized_typescript_source")
        blobs[relpath] = data
    return blobs


def make_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        safe_directory(path)
        return
    safe_directory(path.parent)
    try:
        path.mkdir(mode=0o755)
    except FileExistsError:
        pass
    safe_directory(path)


def existing_matches(path: Path, expected: bytes) -> bool:
    if path.exists() or path.is_symlink():
        if read_file(path, 65536) != expected:
            stop("unapproved_existing_source_mismatch")
        return True
    return False


def install_sources(blobs: dict[str, bytes]) -> tuple[int, int]:
    lock = ROOT / "awg-worker-source-stage.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_nlink != 1):
            stop("unsafe_worker_stage_lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        require_safe_dormant()
        # Reject ALL mismatched existing files before writing any missing ones.
        pending = []
        already = 0
        drift = []
        current = current_directory()
        for relpath, payload in blobs.items():
            target = current / relpath
            label = target.name.upper().replace("-", "_").replace(".", "_")
            if target.exists() or target.is_symlink():
                if read_file(target, 65536) == payload:
                    already += 1
                    print("FI_AWG_WORKER_SOURCE_" + label + "=MATCHED")
                else:
                    drift.append(label)
                    print("FI_AWG_WORKER_SOURCE_" + label + "=DRIFT")
            else:
                pending.append((target, payload))
                print("FI_AWG_WORKER_SOURCE_" + label + "=MISSING")
        # One drift prevents ALL writes, while reporting the complete matrix.
        if drift:
            stop("unapproved_existing_source_mismatch")
        installed = 0
        for dest, payload in pending:
            folder = current
            for part in dest.parent.relative_to(current).parts:
                folder = folder / part
                make_directory(folder)
            try:
                outfd = os.open(dest, os.O_WRONLY | os.O_CREAT |
                                os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
            except FileExistsError:
                stop("concurrent_worker_source_creation")
            try:
                with os.fdopen(outfd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                dest.unlink(missing_ok=True)
                raise
            installed += 1
        for relpath, payload in blobs.items():
            if not existing_matches(current / relpath, payload):
                stop("installed_source_missing")
        return installed, already
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    if not args.stage.is_absolute() or not re.fullmatch(
            r"/run/fi-awg-row-lock\.[A-Za-z0-9]{8}", str(args.stage)):
        stop("unapproved_staging_path")
    require_safe_dormant()
    blobs = approved_sources(args.stage)
    installed, already = install_sources(blobs)
    print("FI_AWG_WORKER_SOURCE=staged;NEW_FILES=" + str(installed) +
          ";EXISTING_MATCHED=" + str(already) +
          ";TOTAL=5;WORKER_STARTED=false;CUSTOMER_RELEASE=false")


if __name__ == "__main__":
    try:
        main()
    except (StageBlocked, OSError, ValueError, TypeError, KeyError,
            UnicodeError, subprocess.SubprocessError):
        raise SystemExit(2)
