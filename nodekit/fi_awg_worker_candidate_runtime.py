#!/usr/bin/env python3
"""Stage and verify FI217's corrected AWG worker dependencies, without activation.

Never change the currently effective systemd worker, the existing /current
controller, release flags, accounts, subscribers, or network paths.
Run only on RU188 while the old reviewed worker is disabled.
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

import fi_awg_worker_candidate_stage as candidate
import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_source_stage as isolated
import fi_awg_worker_isolated_pg_stage as pgstage
import fi_awg_worker_isolated_runtime_preflight as runtime

RELEASE = candidate.CANDIDATE
MODULES = RELEASE / "node_modules"
MARKER = RELEASE / "awg-pg-runtime-manifest.json"
ENTRY = RELEASE / trust.FILES["awg-controller-delivery-worker.ts"]


def verified_sources() -> None:
    candidate.guard()
    manifest = json.loads(trust.read_file(RELEASE / candidate.MARKER, 4096))
    if (not isinstance(manifest, dict) or set(manifest) != {"commit", "files"} or
            manifest["commit"] != candidate.CANDIDATE_COMMIT or
            not isinstance(manifest["files"], dict) or
            set(manifest["files"]) != set(trust.FILES)):
        trust.stop("candidate_source_manifest_mismatch")
    blobs = {}
    for basename, relative in trust.FILES.items():
        digest = manifest["files"][basename]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            trust.stop("candidate_source_hash_invalid")
        contents = trust.read_file(RELEASE / relative)
        candidate.verify_pinned_source_blob(basename, contents)
        if hashlib.sha256(contents).hexdigest() != digest:
            trust.stop("candidate_source_changed")
        blobs[relative] = contents
    isolated.require_source_closure(blobs)
    candidate.verify_nonstandard_imports(blobs)


def expected_runtime(payloads: dict[str, bytes], versions: dict[str, str]) -> bytes:
    data = {
        "commit": candidate.CANDIDATE_COMMIT,
        "packages": {k: versions[k] for k in sorted(versions)},
        "files": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(payloads.items())},
    }
    value = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(value) > 256000:
        trust.stop("candidate_runtime_manifest_oversized")
    return value


def verify_reviewed_runtime_baseline(record: dict) -> None:
    """The candidate may use ONLY the complete already verified old pg graph.

    A candidate manifest cannot approve itself by listing a subset of files,
    replacing the pg source with unreviewed code, or omitting a package.
    """
    try:
        old = json.loads(trust.read_file(pgstage.MARKER, 256000))
    except (ValueError, TypeError, UnicodeError):
        trust.stop("reviewed_runtime_baseline_invalid")
    if (not isinstance(old, dict) or
            set(old) != {"commit", "packages", "files"} or
            old["commit"] != candidate.OLD_COMMIT or
            not isinstance(old["packages"], dict) or
            old["packages"].get("pg") != "8.16.3" or
            not isinstance(old["files"], dict) or
            "pg/package.json" not in old["files"] or
            not 1 <= len(old["packages"]) <= pgstage.MAX_PACKAGES or
            not 1 <= len(old["files"]) <= pgstage.MAX_FILES):
        trust.stop("reviewed_runtime_baseline_untrusted")
    expected = dict(old)
    expected["commit"] = candidate.CANDIDATE_COMMIT
    if record != expected:
        trust.stop("candidate_runtime_differs_from_reviewed_pg_baseline")


def verify_runtime_manifest() -> None:
    verified_sources()
    marker = json.loads(trust.read_file(MARKER, 256000))
    if (not isinstance(marker, dict) or set(marker) != {"commit", "packages", "files"} or
            marker["commit"] != candidate.CANDIDATE_COMMIT or
            not isinstance(marker["packages"], dict) or marker["packages"].get("pg") != "8.16.3" or
            not isinstance(marker["files"], dict) or
            not 1 <= len(marker["packages"]) <= pgstage.MAX_PACKAGES or
            not 1 <= len(marker["files"]) <= pgstage.MAX_FILES):
        trust.stop("candidate_runtime_manifest_invalid")
    verify_reviewed_runtime_baseline(marker)
    for rel, digest in marker["files"].items():
        if (not isinstance(rel, str) or not isinstance(digest, str) or
                not re.fullmatch(r"[0-9a-f]{64}", digest) or
                rel.startswith("/") or ".." in Path(rel).parts or
                not re.fullmatch(
                    r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+",
                    rel)):
            trust.stop("candidate_dependency_manifest_entry_invalid")
        if hashlib.sha256(trust.read_file(MODULES / rel, pgstage.MAX_FILE_BYTES)).hexdigest() != digest:
            trust.stop("candidate_dependency_file_changed")


def node_checks() -> None:
    verify_runtime_manifest()
    runtime.version_compatible()
    node = runtime.trusted_node_binary()
    for rel in trust.FILES.values():
        runtime.command_ok([
            str(node), "--experimental-strip-types", "--check",
            str(RELEASE / rel),
        ], timeout=10)
    # Deliberately use a different process.argv[1], so importing the worker
    # cannot invoke its production main() function.
    code = (
        "import {pathToFileURL} from 'node:url';"
        "if(process.argv[1]!=='__AWG_IMPORT_ONLY__'||!process.argv[2])"
        "process.exit(9);"
        "await import(pathToFileURL(process.argv[2]).href);"
    )
    runtime.command_ok([
        str(node), "--experimental-strip-types", "--input-type=module",
        "-e", code, "__AWG_IMPORT_ONLY__", str(ENTRY),
    ], timeout=18)


def stage() -> tuple[int, int, int]:
    verified_sources()
    payloads, versions = pgstage.gather()
    manifest = expected_runtime(payloads, versions)
    verify_reviewed_runtime_baseline(json.loads(manifest))
    lock = trust.ROOT / "awg-worker-source-stage.lock"
    fd = os.open(
        lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_nlink != 1):
            trust.stop("candidate_runtime_lock_unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        verified_sources()
        # Re-check the reviewed old dependency identity under the same lock.
        verify_reviewed_runtime_baseline(json.loads(manifest))
        if MODULES.exists() or MODULES.is_symlink():
            trust.safe_directory(MODULES)
        marker_exists = MARKER.exists() or MARKER.is_symlink()
        if marker_exists and trust.read_file(MARKER, 256000) != manifest:
            trust.stop("candidate_runtime_manifest_drift")
        missing = []
        matched = 0
        for relative, payload in sorted(payloads.items()):
            target = MODULES / relative
            if target.exists() or target.is_symlink():
                if trust.read_file(target, pgstage.MAX_FILE_BYTES) != payload:
                    trust.stop("candidate_existing_dependency_drift")
                matched += 1
            else:
                missing.append((target, payload))
        if marker_exists and missing:
            trust.stop("candidate_complete_manifest_partial_runtime")
        if not MODULES.exists():
            trust.make_directory(MODULES)
        for destination, payload in missing:
            folder = MODULES
            for name in destination.parent.relative_to(MODULES).parts:
                folder = folder / name
                trust.make_directory(folder)
            pgstage.put_if_missing(destination, payload)
        for relative, payload in payloads.items():
            if trust.read_file(MODULES / relative, pgstage.MAX_FILE_BYTES) != payload:
                trust.stop("candidate_dependency_postcheck_failed")
        if not marker_exists:
            pgstage.put_if_missing(MARKER, manifest)
        verify_runtime_manifest()
        # Last: validate real Node/TypeScript imports against isolated modules.
        node_checks()
        candidate.guard()
        return len(missing), matched, len(versions)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("stage", "verify"), required=True)
    args = parser.parse_args()
    if args.mode == "stage":
        new, matched, count = stage()
        print(f"FI_AWG_CANDIDATE_RUNTIME=STAGED;NEW={new};MATCHED={matched};"
              f"PACKAGES={count};MODULE_IMPORT=PASS;"
              "EFFECTIVE_RELEASE=LEGACY_DISABLED;CUSTOMER_RELEASE=false")
    else:
        node_checks()
        candidate.guard()
        print("FI_AWG_CANDIDATE_RUNTIME=VERIFIED;MODULE_IMPORT=PASS;"
              "EFFECTIVE_RELEASE=LEGACY_DISABLED;CUSTOMER_RELEASE=false")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (trust.StageBlocked, OSError, ValueError, TypeError, KeyError,
            UnicodeError, RuntimeError):
        raise SystemExit(2)
