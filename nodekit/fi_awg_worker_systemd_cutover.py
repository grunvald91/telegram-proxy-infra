#!/usr/bin/env python3
"""RU188: atomically select reviewed FI217 worker in an INACTIVE systemd unit.

The existing disabled worker is never started, enabled, restarted or granted
database release. The old exact drop-in is backed up before the swap and
restored automatically if any post-swap check fails. A failed/aborted process
cannot enable a worker: the existing approval marker remains absent.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_source_stage as isolated
import fi_awg_worker_isolated_systemd_stage as systemd
import fi_awg_worker_candidate_stage as candidate
import fi_awg_worker_candidate_runtime as runtime
import fi_awg_worker_isolated_pg_stage as pgstage

OVERRIDE = systemd.OVERRIDE
BACKUP_DIR = trust.ROOT / "awg-worker-systemd-backups"
BACKUP = BACKUP_DIR / ("fi217-" + candidate.OLD_COMMIT + "-90-isolated-awg-worker.conf.backup")
LOCK = trust.ROOT / "awg-worker-source-stage.lock"
NODE = trust.CURRENT / "bin/node"
ENTRY = runtime.ENTRY


def expected_new_dropin() -> bytes:
    # Preserve the exact old unit's sandbox/approval conditions; change only
    # the immutable worker source and working directory, never /current.
    raw = systemd.expected_dropin().decode("ascii")
    old_root = str(isolated.RELEASE)
    new_root = str(candidate.CANDIDATE)
    if raw.count(old_root) != 2 or old_root == new_root:
        trust.stop("cutover_unexpected_legacy_dropin_template")
    return raw.replace(old_root, new_root).encode("ascii")


def reload_definitions() -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", "daemon-reload"], capture_output=True,
        stdin=subprocess.DEVNULL, timeout=18, check=False)
    if result.returncode:
        trust.stop("cutover_daemon_reload_failed")


def fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_replace(payload: bytes) -> None:
    # .new does not end in .conf and cannot become a systemd drop-in.
    trust.safe_directory(systemd.DIR)
    temp = systemd.DIR / (".90-isolated-awg-worker.conf.new." + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(payload)
            file.flush()
            os.fchmod(file.fileno(), 0o644)
            os.fsync(file.fileno())
        os.replace(temp, OVERRIDE)
        fsync_directory(systemd.DIR)
    finally:
        temp.unlink(missing_ok=True)


def persist_backup(legacy_payload: bytes) -> None:
    if not (BACKUP_DIR.exists() or BACKUP_DIR.is_symlink()):
        trust.make_directory(BACKUP_DIR)
    else:
        trust.safe_directory(BACKUP_DIR)
    if BACKUP.exists() or BACKUP.is_symlink():
        if trust.read_file(BACKUP, 8192) != legacy_payload:
            trust.stop("cutover_backup_drift")
        return
    fd = os.open(BACKUP, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(legacy_payload)
            file.flush()
            os.fsync(file.fileno())
        fsync_directory(BACKUP_DIR)
    except BaseException:
        BACKUP.unlink(missing_ok=True)
        raise


def verified_backup(expected_old: bytes) -> None:
    if trust.read_file(BACKUP, 8192) != expected_old:
        trust.stop("cutover_backup_missing_or_changed")


def verify_candidate_artifacts() -> None:
    """Verify new release independently of the old unit's effective pointer."""
    source = json.loads(trust.read_file(candidate.CANDIDATE / candidate.MARKER, 4096))
    if (not isinstance(source, dict) or set(source) != {"commit", "files"} or
            source["commit"] != candidate.CANDIDATE_COMMIT or
            not isinstance(source["files"], dict) or
            set(source["files"]) != set(trust.FILES)):
        trust.stop("cutover_candidate_source_manifest_invalid")
    blobs = {}
    for name, relative in trust.FILES.items():
        digest = source["files"][name]
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            trust.stop("cutover_candidate_source_digest_invalid")
        blob = trust.read_file(candidate.CANDIDATE / relative)
        candidate.verify_pinned_source_blob(name, blob)
        if hashlib.sha256(blob).hexdigest() != digest:
            trust.stop("cutover_candidate_source_changed")
        blobs[relative] = blob
    isolated.require_source_closure(blobs)
    candidate.verify_nonstandard_imports(blobs)

    meta = json.loads(trust.read_file(runtime.MARKER, 256000))
    if (not isinstance(meta, dict) or set(meta) != {"commit", "files", "packages"} or
            meta["commit"] != candidate.CANDIDATE_COMMIT or
            not isinstance(meta["files"], dict) or
            not isinstance(meta["packages"], dict) or
            not 1 <= len(meta["files"]) <= pgstage.MAX_FILES or
            not 1 <= len(meta["packages"]) <= pgstage.MAX_PACKAGES):
        trust.stop("cutover_candidate_runtime_manifest_invalid")
    runtime.verify_reviewed_runtime_baseline(meta)
    for name, digest in meta["files"].items():
        if (not isinstance(name, str) or not re.fullmatch(
                r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+",
                name) or not isinstance(digest, str) or
                not re.fullmatch(r"[a-f0-9]{64}", digest)):
            trust.stop("cutover_dependency_file_path_invalid")
        if hashlib.sha256(trust.read_file(runtime.MODULES / name,
                                         pgstage.MAX_FILE_BYTES)).hexdigest() != digest:
            trust.stop("cutover_dependency_file_changed")
    runtime.runtime.version_compatible()
    node = runtime.runtime.trusted_node_binary()
    for rel in trust.FILES.values():
        runtime.runtime.command_ok(
            [str(node), "--experimental-strip-types", "--check",
             str(candidate.CANDIDATE / rel)], timeout=10)
    # Import, do not execute main() or dispatch any real or synthetic grants.
    code = (
        "import {pathToFileURL} from 'node:url';"
        "if(process.argv[1]!=='__AWG_IMPORT_ONLY__'||!process.argv[2])"
        "process.exit(9);await import(pathToFileURL(process.argv[2]).href);"
    )
    runtime.runtime.command_ok(
        [str(node), "--experimental-strip-types", "--input-type=module",
         "-e", code, "__AWG_IMPORT_ONLY__", str(ENTRY)], timeout=18)


def verified_new_effective_unit(payload: bytes) -> None:
    systemd.dormant_and_disabled()
    systemd.approved_base_unit()
    if trust.read_file(OVERRIDE, 8192) != payload:
        trust.stop("cutover_effective_dropin_bytes_changed")
    if systemd.show("LoadState") != "loaded":
        trust.stop("cutover_systemd_not_loaded")
    if systemd.show("FragmentPath") != str(systemd.BASE):
        trust.stop("cutover_systemd_base_changed")
    if systemd.show("NeedDaemonReload") != "no":
        trust.stop("cutover_systemd_needs_reload")
    if systemd.show("DropInPaths").split() != [str(OVERRIDE)]:
        trust.stop("cutover_unknown_systemd_dropin")
    if systemd.show("WorkingDirectory") != str(candidate.CANDIDATE):
        trust.stop("cutover_wrong_effective_directory")
    details = systemd.show("ExecStart")
    matches = re.findall(r"(?:^|[;{]\s*)argv\[\]=([^;]+)", details)
    if (len(matches) != 1 or details.count("argv[]=") != 1 or
            matches[0].strip() !=
            f"{NODE} --experimental-strip-types {ENTRY}" or
            f"path={NODE}" not in details):
        trust.stop("cutover_wrong_effective_command")
    systemd.dormant_and_disabled()


def legacy_preflight(expected_old: bytes) -> None:
    systemd.dormant_and_disabled()
    systemd.approved_base_unit()
    systemd.exact_effective_unit()
    systemd.source_verified()
    if trust.read_file(OVERRIDE, 8192) != expected_old:
        trust.stop("cutover_legacy_dropin_changed")
    # This is only valid while systemd still selects the old release.
    runtime.node_checks()


def acquire_lock() -> int:
    trust.safe_directory(trust.ROOT)
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    meta = os.fstat(fd)
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
            meta.st_mode & 0o077 or meta.st_nlink != 1):
        os.close(fd)
        trust.stop("cutover_lock_unsafe")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd



def restore_legacy_after_failure(old: bytes) -> None:
    """Restore a fully verified legacy definition after interrupted cutover."""
    try:
        atomic_replace(old)
        reload_definitions()
        if trust.read_file(OVERRIDE, 8192) != old:
            trust.stop("cutover_restored_dropin_drift")
        systemd.exact_effective_unit()
        systemd.dormant_and_disabled()
    except BaseException:
        trust.stop("cutover_rollback_failed")


def switch() -> str:
    old = systemd.expected_dropin()
    new = expected_new_dropin()
    fd = acquire_lock()
    try:
        # Locked recheck prevents concurrent staging/replacement.
        systemd.dormant_and_disabled()
        systemd.approved_base_unit()
        current = trust.read_file(OVERRIDE, 8192)
        if current == new:
            verified_backup(old)
            try:
                verify_candidate_artifacts()
                # If a previous job was terminated between os.replace and
                # daemon-reload, reconcile the effective unit on this rerun.
                reload_definitions()
                verified_new_effective_unit(new)
            except BaseException:
                restore_legacy_after_failure(old)
                trust.stop("cutover_rolled_back_after_interrupted_switch")
            return "UNCHANGED"
        if current != old:
            trust.stop("cutover_unknown_existing_dropin")
        legacy_preflight(old)
        verify_candidate_artifacts()
        persist_backup(old)
        # All checks and backup have succeeded. No change to systemd enablement.
        try:
            atomic_replace(new)
            reload_definitions()
            verified_backup(old)
            verify_candidate_artifacts()
            verified_new_effective_unit(new)
        except BaseException:
            # Roll back even if daemon-reload or a postcondition failed.
            # Never start, restart, enable or modify the base unit.
            restore_legacy_after_failure(old)
            trust.stop("cutover_rolled_back_after_failure")
        return "SWITCHED"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def verify() -> None:
    old = systemd.expected_dropin()
    new = expected_new_dropin()
    fd = acquire_lock()
    try:
        verified_backup(old)
        verify_candidate_artifacts()
        verified_new_effective_unit(new)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("switch", "verify"), required=True)
    args = parser.parse_args()
    if args.mode == "switch":
        result = switch()
        print(f"FI_AWG_SYSTEMD_CUTOVER=VERIFIED;CHANGE={result};"
              "ROLLBACK_BACKUP=PINNED;UNIT_ACTIVE=false;CUSTOMER_RELEASE=false")
    else:
        verify()
        print("FI_AWG_SYSTEMD_CUTOVER=READONLY_VERIFIED;"
              "UNIT_ACTIVE=false;CUSTOMER_RELEASE=false")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (trust.StageBlocked, OSError, ValueError, TypeError, KeyError,
            UnicodeError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit(2)
