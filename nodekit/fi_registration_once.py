#!/usr/bin/env python3
"""Guarded, one-shot FI registration on existing RU188.

Only starts the preinstalled root-only systemd enrollment unit when the
existing PostgreSQL inventory is independently approved and all local trust
materials are protected. Does not approve inventory, copy secrets or publish.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys

RU = "188.120.254.223"
NODE = "fi-test-01"
HOST = "fi.mnebyvpn.site"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
ROOT = Path("/root/mnebyvpn-controller")
UNIT_NAME = "mnebyvpn-fi-enrollment.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class GateError(Exception):
    pass


def fail(reason: str) -> None:
    print("FI_REGISTRATION_BLOCKED=" + reason, file=sys.stderr)
    raise GateError(reason)


def assigned_ip(ip: str) -> bool:
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                raw = fcntl.ioctl(s.fileno(), 0x8915,
                                  struct.pack("256s", name.encode()))
                if socket.inet_ntoa(raw[20:24]) == ip:
                    return True
            except OSError:
                pass
    return False


def protected(path: Path, max_size: int = 16384) -> bytes:
    for parent in path.parents:
        st = parent.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o022):
            fail("untrusted_parent_directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o077 or st.st_nlink != 1 or
                not 1 <= st.st_size <= max_size):
            fail("unsafe_protected_file")
        data = os.read(fd, max_size + 1)
        if len(data) != st.st_size:
            fail("protected_file_changed")
        return data
    finally:
        os.close(fd)


def spki(path: Path, fingerprint: str) -> bytes:
    blob = protected(path, 100)
    if (len(blob) != 44 or not blob.startswith(SPKI_PREFIX) or
            hashlib.sha256(blob).hexdigest() != fingerprint):
        fail("public_identity_mismatch")
    return blob


def execute(args: list[str], timeout: int = 12) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("local_command_unavailable")
    if p.returncode != 0:
        fail("local_command_failed")
    return p.stdout.strip()


def db_state(expected_spki: str) -> str:
    # Read-only query. This deployment must already contain the approved row.
    query = ("SELECT status || '|' || endpoint_host || '|' || "
             "identity_public_spki || '|' || "
             "(approved_at IS NOT NULL)::text || '|' || "
             "(enrolled_at IS NOT NULL)::text "
             "FROM public.vpn_node_enrollment_inventory "
             "WHERE node_id='fi-test-01';")
    raw = execute(["docker", "exec", "mnebyvpn-stage-postgres", "psql",
                   "-AtX", "-v", "ON_ERROR_STOP=1", "-U", "mnebyvpn_stage",
                   "-d", "mnebyvpn_stage", "-c", query])
    parts = raw.split("|")
    if len(parts) != 5 or parts[0] not in ("approved", "enrolled"):
        fail("fi_inventory_absent_or_not_approved")
    status, host, public, approved, enrolled = parts
    if (host != HOST or public != expected_spki or approved != "true" or
            (status == "enrolled") != (enrolled == "true")):
        fail("fi_inventory_identity_or_state_mismatch")
    return status


def require_runtime() -> None:
    current = Path("/opt/mnebyvpn-controller/current")
    if not current.is_symlink() or not current.resolve(strict=True).is_dir():
        fail("controller_runtime_missing")
    unit = protected(UNIT_PATH, 20000).decode("utf-8")
    required = (
        "Type=oneshot",
        "User=root",
        "ConditionPathExists=/root/mnebyvpn-controller/approvals/fi-enrollment.enable",
        "ConditionPathExists=/root/mnebyvpn-controller/config/fi-enrollment.env",
        "ExecStart=/opt/mnebyvpn-controller/current/bin/node --experimental-strip-types ",
        "IPAddressDeny=any",
        "IPAddressAllow=217.11.167.91/32",
        "NoNewPrivileges=yes",
    )
    if any(s not in unit for s in required):
        fail("enrollment_systemd_unit_untrusted")
    for root in ("/etc/systemd/system", "/run/systemd/system",
                 "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
                 "/lib/systemd/system"):
        override = Path(root, UNIT_NAME + ".d")
        if override.exists() or override.is_symlink():
            fail("enrollment_systemd_override_present")
    for name in ("config/fi-enrollment.env", "approvals/fi-enrollment.enable"):
        protected(ROOT / name, 8192)


def main() -> int:
    if os.geteuid() != 0 or not assigned_ip(RU):
        fail("not_existing_ru188_root")
    spki(ROOT / "controller-public.spki", CONTROLLER_SHA)
    node = spki(ROOT / "fi-node-public.spki", NODE_SHA)
    expected = base64.urlsafe_b64encode(node).decode("ascii").rstrip("=")
    known = protected(ROOT / "fi-known_hosts", 512).decode("ascii")
    if not known.startswith(HOST + " ssh-ed25519 ") or len(known.splitlines()) != 1:
        fail("fi_ssh_host_key_unpinned")
    protected(ROOT / "controller-signing-key.pem", 8192)
    protected(ROOT / "fi-enrollment-ssh", 8192)
    before = db_state(expected)
    if before == "enrolled":
        print("FI_REGISTRATION=enrolled;SUBSCRIBER_PUBLICATION=false;IDEMPOTENT=true")
        return 0
    require_runtime()
    execute(["systemctl", "start", UNIT_NAME], timeout=85)
    # systemd ConditionPathExists skips can exit 0: DB readback is mandatory.
    if db_state(expected) != "enrolled":
        fail("registration_service_did_not_enroll_fi")
    print("FI_REGISTRATION=enrolled;SUBSCRIBER_PUBLICATION=false;IDEMPOTENT=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, OSError, ValueError, UnicodeError):
        raise SystemExit(2)
