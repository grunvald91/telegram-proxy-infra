#!/usr/bin/env python3
"""Read-only RU188 readiness audit for an isolated AWG worker source release.

Does not create module links, install packages, change unit files, run the
delivery worker, contact FI, or publish client profiles.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_source_stage as isolated

RELEASE = isolated.RELEASE


def module_manifest_matches() -> None:
    isolated.verify_ancestry()
    manifest = json.loads(trust.read_file(RELEASE / isolated.MARKER, 4096))
    if (not isinstance(manifest, dict) or set(manifest) != {"commit", "files"}
            or manifest["commit"] != trust.PINNED_COMMIT
            or not isinstance(manifest["files"], dict)
            or set(manifest["files"]) != set(trust.FILES)):
        raise ValueError("unapproved_worker_manifest")
    verified = {}
    for basename, rel in trust.FILES.items():
        raw = trust.read_file(RELEASE / rel)
        if hashlib.sha256(raw).hexdigest() != manifest["files"][basename]:
            raise ValueError("isolated_worker_source_mismatch")
        verified[rel] = raw
    isolated.require_source_closure(verified)


def trusted_node_binary() -> Path:
    current = trust.current_directory()
    binary = current / "bin/node"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("node_runtime_unavailable")
    return binary


def command_ok(cmd: list[str], *, timeout: int = 15) -> None:
    outcome = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False, stdin=subprocess.DEVNULL)
    if outcome.returncode != 0:
        raise ValueError("isolated_node_check_failed")


def version_compatible() -> None:
    binary = trusted_node_binary()
    out = subprocess.run([str(binary), "--version"], capture_output=True,
                         text=True, timeout=8, check=False,
                         stdin=subprocess.DEVNULL)
    if out.returncode:
        raise ValueError("node_version_unavailable")
    import re
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)\n?", out.stdout)
    if not match or int(match.group(1)) < 22:
        raise ValueError("node_version_unsupported")


def module_parsing() -> None:
    binary = trusted_node_binary()
    for path in trust.FILES.values():
        command_ok([str(binary), "--experimental-strip-types", "--check",
                    str(RELEASE / path)])


def pg_resolution_from_current() -> None:
    binary = trusted_node_binary()
    current = trust.current_directory()
    check = ("const p=require.resolve('pg',{paths:[process.argv[1]]});"
             "if(!p.endsWith('.js'))process.exit(2)")
    command_ok([str(binary), "-e", check, str(current / "apps/service/src")])


def check(label: str, action) -> bool:
    try:
        action()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.SubprocessError, subprocess.TimeoutExpired):
        print(f"FI_AWG_ISOLATED_RUNTIME_{label}=BLOCKED")
        return False
    print(f"FI_AWG_ISOLATED_RUNTIME_{label}=OK")
    return True


def main() -> int:
    # Identity, inactive worker, no approval, unpublished FI enrollment and
    # canonical DB access must pass before any protected source is inspected.
    if not check("CONTROLLER_GATES", trust.require_safe_dormant):
        print("FI_AWG_ISOLATED_RUNTIME_PREFLIGHT=BLOCKED;WORKER_STARTED=false;CUSTOMER_RELEASE=false")
        return 2
    outcome = [
        check("SOURCE_MANIFEST", module_manifest_matches),
        check("NODE_VERSION", version_compatible),
        check("TYPESCRIPT_SYNTAX", module_parsing),
        check("SHARED_PG_RESOLUTION", pg_resolution_from_current),
    ]
    # Intentionally no runtime symlink here. No service may start at this stage.
    if not all(outcome):
        print("FI_AWG_ISOLATED_RUNTIME_PREFLIGHT=BLOCKED;WORKER_STARTED=false;CUSTOMER_RELEASE=false")
        return 2
    print("FI_AWG_ISOLATED_RUNTIME_PREFLIGHT=READONLY_READY;WORKER_STARTED=false;"
          "CUSTOMER_RELEASE=false;RUNTIME_ATTACHED=false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
