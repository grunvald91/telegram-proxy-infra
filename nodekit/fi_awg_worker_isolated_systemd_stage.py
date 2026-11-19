#!/usr/bin/env python3
"""RU188: stage ONLY a pinned AWG worker systemd drop-in, service stays OFF.

This modifies systemd's on-disk *inactive* unit configuration, not /current,
the controller, any DNS/proxy/VPN flows, entitlement, or client profile.
Activation is forbidden: approval marker must be absent and unit disabled.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_source_stage as isolated
import fi_awg_worker_isolated_pg_stage as pgstage
import fi_awg_worker_isolated_runtime_preflight as runtime

SERVICE = "mnebyvpn-awg-delivery.service"
BASE = Path("/etc/systemd/system") / SERVICE
DIR = Path("/etc/systemd/system") / (SERVICE + ".d")
OVERRIDE = DIR / "90-isolated-awg-worker.conf"
WORKER = isolated.RELEASE / trust.FILES["awg-controller-delivery-worker.ts"]


def show(prop: str) -> str:
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", "-p", prop, "--value", SERVICE],
        text=True, capture_output=True, timeout=8, check=False,
        stdin=subprocess.DEVNULL)
    if result.returncode or len(result.stdout) > 8192:
        trust.stop("systemd_property_unavailable")
    return result.stdout.strip()


def dormant_and_disabled() -> None:
    trust.require_safe_dormant()
    if show("ActiveState") != "inactive" or show("UnitFileState") not in ("disabled", "static"):
        trust.stop("systemd_worker_not_dormant_disabled")
    if show("SubState") not in ("dead", "failed"):
        trust.stop("systemd_worker_substate_unexpected")
    flag = trust.ROOT / "approvals/awg-delivery.enable"
    if flag.exists() or flag.is_symlink():
        trust.stop("systemd_approval_flag_present")


def source_verified() -> None:
    runtime.module_manifest_matches()
    # Verify the independently staged package manifest hashes, no implicit
    # dependency fallback to the mutable /current/node_modules package tree.
    meta = json.loads(trust.read_file(pgstage.MARKER, 256000))
    if (not isinstance(meta, dict) or set(meta) != {"commit", "packages", "files"} or
            meta["commit"] != trust.PINNED_COMMIT or
            not isinstance(meta["packages"], dict) or
            meta["packages"].get("pg") != "8.16.3" or
            not isinstance(meta["files"], dict) or
            not 1 <= len(meta["packages"]) <= 40 or
            not 1 <= len(meta["files"]) <= 2500):
        trust.stop("isolated_dependencies_manifest_invalid")
    for name, digest in meta["files"].items():
        if (not isinstance(name, str) or not re.fullmatch(
                r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+",
                name) or ".." in Path(name).parts or
                not isinstance(digest, str) or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            trust.stop("isolated_dependency_manifest_entry_invalid")
        if hashlib.sha256(trust.read_file(pgstage.MODULES / name,
                                         pgstage.MAX_FILE_BYTES)).hexdigest() != digest:
            trust.stop("isolated_dependency_file_drift")
    runtime.version_compatible()
    runtime.module_parsing()
    runtime.isolated_module_import()


def expected_dropin() -> bytes:
    node = trust.CURRENT / "bin/node"
    if not (trust.current_directory() / "bin/node").is_file():
        trust.stop("isolated_node_binary_missing")
    text = (
        "[Service]\n"
        "# The original unit conditions and network/FS sandbox remain unchanged.\n"
        "WorkingDirectory=" + str(isolated.RELEASE) + "\n"
        "ExecStart=\n"
        "ExecStart=" + str(node) + " --experimental-strip-types " +
        str(WORKER) + "\n"
    )
    return text.encode("ascii")


def approved_base_unit() -> None:
    raw = trust.read_file(BASE, 8192)
    if raw.count(b"[Service]") != 1 or raw.count(b"[Unit]") != 1:
        trust.stop("unexpected_awg_base_unit_sections")
    required = (
        b"ConditionPathExists=/root/mnebyvpn-controller/approvals/awg-delivery.enable",
        b"EnvironmentFile=/root/mnebyvpn-controller/config/awg-delivery.env",
        b"ExecStart=/opt/mnebyvpn-controller/current/bin/node --experimental-strip-types "
        b"/opt/mnebyvpn-controller/current/apps/service/src/awg-controller-delivery-worker.ts",
        b"Restart=no", b"ProtectSystem=strict", b"NoNewPrivileges=yes",
        b"IPAddressDeny=any", b"IPAddressAllow=217.11.167.91/32",
    )
    for item in required:
        if raw.count(item) != 1:
            trust.stop("unexpected_awg_base_unit_contract")


def verify_dropin_paths() -> None:
    paths = show("DropInPaths").split()
    if paths not in ([], [str(OVERRIDE)]):
        trust.stop("unapproved_awg_unit_dropin")


def exact_effective_unit() -> None:
    if show("DropInPaths").split() != [str(OVERRIDE)]:
        trust.stop("isolated_awg_dropin_not_loaded")
    if show("WorkingDirectory") != str(isolated.RELEASE):
        trust.stop("isolated_awg_working_directory_not_effective")
    command = show("ExecStart")
    if (command.count("argv[]=") != 1 or
            command.count(str(WORKER)) != 1 or
            "/current/apps/service/src/awg-controller-delivery-worker.ts" in command or
            "--experimental-strip-types" not in command or
            str(trust.CURRENT / "bin/node") not in command):
        trust.stop("isolated_awg_execstart_not_effective")


def stage() -> str:
    dormant_and_disabled()
    approved_base_unit()
    source_verified()
    trust.safe_directory(DIR.parent)
    verify_dropin_paths()
    payload = expected_dropin()
    if OVERRIDE.exists() or OVERRIDE.is_symlink():
        if trust.read_file(OVERRIDE, 8192) != payload:
            trust.stop("existing_awg_dropin_drift")
        operation = "UNCHANGED"
    else:
        if DIR.exists() or DIR.is_symlink():
            trust.safe_directory(DIR)
        else:
            trust.make_directory(DIR)
        try:
            fd = os.open(OVERRIDE, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        except FileExistsError:
            trust.stop("concurrent_awg_dropin_write")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            OVERRIDE.unlink(missing_ok=True)
            raise
        operation = "CREATED"
    # This is a definition reload, NEVER a service start/restart/enable.
    done = subprocess.run(
        ["/usr/bin/systemctl", "daemon-reload"],
        capture_output=True, text=True, timeout=18, check=False,
        stdin=subprocess.DEVNULL)
    if done.returncode != 0:
        trust.stop("systemd_daemon_reload_failed")
    approved_base_unit()
    exact_effective_unit()
    dormant_and_disabled()
    return operation


def main() -> int:
    status = stage()
    print("FI_AWG_ISOLATED_SYSTEMD=STAGED;DROPIN=" + status +
          ";UNIT_DISABLED=true;WORKER_STARTED=false;CUSTOMER_RELEASE=false")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (trust.StageBlocked, OSError, ValueError, TypeError, KeyError,
            UnicodeError, subprocess.SubprocessError):
        raise SystemExit(2)
