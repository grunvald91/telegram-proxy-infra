#!/usr/bin/env python3
"""RU188-only immutable pg@8.16.3 runtime staging for isolated AWG worker.

Copy only already-installed pg and declared runtime dependencies to the
versioned isolated AWG release. No npm network, live /current modification,
symlinks, unit changes, approval, process starts, billing writes or peers.
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
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_source_stage as isolated
import fi_awg_worker_isolated_runtime_preflight as runtime

MODULES = isolated.RELEASE / "node_modules"
MARKER = isolated.RELEASE / "awg-pg-runtime-manifest.json"
PKG = re.compile(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+")
MAX_PACKAGES = 40
MAX_FILES = 2500
MAX_BYTES = 24 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024


def package_name(name: str) -> str:
    if (not isinstance(name, str) or not PKG.fullmatch(name) or
            any(part in (".", "..") for part in name.split("/"))):
        trust.stop("unapproved_dependency_name")
    return name


def source_packages() -> Path:
    folder = trust.current_directory() / "node_modules"
    trust.safe_directory(folder)
    return folder


def dependencies(pkg: dict) -> set[str]:
    deps = pkg.get("dependencies", {})
    optional = pkg.get("optionalDependencies", {})
    if not isinstance(deps, dict) or not isinstance(optional, dict):
        trust.stop("unreviewed_package_dependencies")
    return {package_name(k) for k in deps}, {package_name(k) for k in optional}


def gather() -> tuple[dict[str, bytes], dict[str, str]]:
    source = source_packages()
    queue = ["pg"]
    scanned: set[str] = set()
    payloads: dict[str, bytes] = {}
    versions: dict[str, str] = {}
    total = 0
    while queue:
        name = package_name(queue.pop())
        if name in scanned:
            continue
        if len(scanned) >= MAX_PACKAGES:
            trust.stop("dependency_package_limit")
        folder = source / name
        trust.safe_directory(folder)
        if not folder.is_relative_to(source):
            trust.stop("dependency_path_outside_source")
        try:
            package = json.loads(trust.read_file(folder / "package.json", 65536))
        except (ValueError, UnicodeError, TypeError):
            trust.stop("invalid_dependency_package_json")
        if (not isinstance(package, dict) or package.get("name") != name or
                not isinstance(package.get("version"), str) or
                not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?",
                                 package["version"])):
            trust.stop("dependency_identity_mismatch")
        if name == "pg" and package["version"] != "8.16.3":
            trust.stop("pg_version_not_approved")
        needed, optional = dependencies(package)
        for dep in needed:
            trust.safe_directory(source / dep)
            queue.append(dep)
        for dep in optional:
            if (source / dep).exists() or (source / dep).is_symlink():
                trust.safe_directory(source / dep)
                queue.append(dep)
        versions[name] = package["version"]
        scanned.add(name)
        for root, dirs, files in os.walk(folder, followlinks=False):
            here = Path(root)
            trust.safe_directory(here)
            for dirname in dirs:
                trust.safe_directory(here / dirname)
            for filename in files:
                path = here / filename
                rel = path.relative_to(source).as_posix()
                if rel in payloads:
                    trust.stop("duplicate_dependency_file")
                if len(payloads) >= MAX_FILES:
                    trust.stop("dependency_file_limit")
                blob = trust.read_file(path, MAX_FILE_BYTES)
                total += len(blob)
                if total > MAX_BYTES:
                    trust.stop("dependency_byte_limit")
                payloads[rel] = blob
    if not payloads or "pg/package.json" not in payloads:
        trust.stop("pg_dependency_closure_empty")
    return payloads, versions


def put_if_missing(path: Path, data: bytes) -> bool:
    if path.exists() or path.is_symlink():
        if trust.read_file(path, MAX_FILE_BYTES) != data:
            trust.stop("isolated_dependency_drift")
        return False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        trust.stop("concurrent_dependency_creation")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


def stage() -> tuple[int, int, int]:
    trust.require_safe_dormant()
    runtime.module_manifest_matches()
    payloads, versions = gather()
    expected = {
        "commit": trust.PINNED_COMMIT,
        "packages": {k: versions[k] for k in sorted(versions)},
        "files": {k: hashlib.sha256(v).hexdigest()
                  for k, v in sorted(payloads.items())},
    }
    manifest = (json.dumps(expected, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("ascii")
    if len(manifest) > 256000:
        trust.stop("dependency_manifest_limit")
    lock = trust.ROOT / "awg-worker-source-stage.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_nlink != 1):
            trust.stop("untrusted_dependency_stage_lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        trust.require_safe_dormant()
        runtime.module_manifest_matches()
        if MODULES.exists() or MODULES.is_symlink():
            trust.safe_directory(MODULES)
        if MARKER.exists() or MARKER.is_symlink():
            if trust.read_file(MARKER, 256000) != manifest:
                trust.stop("existing_dependency_manifest_changed")
        # Preflight all existing files before creating any missing data.
        missing: list[tuple[Path, bytes]] = []
        matched = 0
        for name, data in sorted(payloads.items()):
            target = MODULES / name
            if target.exists() or target.is_symlink():
                if trust.read_file(target, MAX_FILE_BYTES) != data:
                    trust.stop("existing_isolated_package_drift")
                matched += 1
            else:
                missing.append((target, data))
        if (MARKER.exists() or MARKER.is_symlink()) and missing:
            trust.stop("partial_dependency_stage_with_manifest")
        if not (MODULES.exists() or MODULES.is_symlink()):
            trust.make_directory(MODULES)
        written = 0
        for target, data in missing:
            folder = MODULES
            for part in target.parent.relative_to(MODULES).parts:
                folder = folder / part
                if folder.exists() or folder.is_symlink():
                    trust.safe_directory(folder)
                else:
                    trust.make_directory(folder)
            if put_if_missing(target, data):
                written += 1
        # Full verification before publishing the final manifest.
        for name, data in payloads.items():
            if trust.read_file(MODULES / name, MAX_FILE_BYTES) != data:
                trust.stop("dependency_verification_failed")
        if not (MARKER.exists() or MARKER.is_symlink()):
            put_if_missing(MARKER, manifest)
        return written, matched, len(versions)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", type=Path, required=True)
    args = p.parse_args()
    if (not args.stage.is_absolute() or not re.fullmatch(
            r"/run/fi-awg-row-lock\.[A-Za-z0-9]{8}", str(args.stage)) or
            not args.stage.is_dir()):
        trust.stop("unapproved_dependency_stage_path")
    new, matched, packages = stage()
    print(f"FI_AWG_ISOLATED_PG=STAGED;NEW={new};MATCHED={matched};"
          f"PACKAGES={packages};WORKER_STARTED=false;CUSTOMER_RELEASE=false")


if __name__ == "__main__":
    try:
        main()
    except (trust.StageBlocked, OSError, TypeError, ValueError,
            UnicodeError, KeyError):
        raise SystemExit(2)
