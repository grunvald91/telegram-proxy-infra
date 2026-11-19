#!/usr/bin/env python3
"""FI217 dedicated AWG SSH forced command (no shell, no listener).

Only an independently pinned controller-signed AWG lease reaches the existing
Nodekit AWG apply operation. Inactive AWG + watchdog always fail closed.
The bounded preflight does not modify peers, subscriptions, DB or systemd.
Must be installed root-owned in /opt/mnebyvpn-nodekit via guarded bootstrap.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
HANDLER = Path("/opt/mnebyvpn-nodekit/awg_peer_grants.py")
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
PREFLIGHT = b"MNEBYVPN_AWG_DELIVERY_PREFLIGHT_V1\n"
FIELDS = {"nodeId", "op", "entitlementId", "revision", "peerPublicKey",
          "clientIpv4", "expiresAt", "issuedAt", "nonce", "signature"}
MAX_COMMAND = 4096


class DeliveryDenied(ValueError):
    pass


def deny(code: str) -> None:
    print("FI_AWG_DELIVERY_DENIED=" + code, file=sys.stderr)
    raise DeliveryDenied(code)


def owned_file(path: Path, maximum: int) -> bytes:
    # The executable and trust files must not be symlinked or caller-writable.
    if not path.is_absolute():
        deny("untrusted_path")
    for directory in path.parents:
        try:
            s = directory.lstat()
        except OSError:
            deny("missing_protected_parent")
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            deny("untrusted_protected_parent")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        deny("missing_protected_file")
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
                s.st_mode & 0o022 or s.st_nlink != 1 or not 1 <= s.st_size <= maximum):
            deny("untrusted_protected_file")
        blob = os.read(fd, maximum + 1)
        if len(blob) != s.st_size:
            deny("protected_file_changed")
        return blob
    finally:
        os.close(fd)


def check_identity() -> None:
    import hashlib
    prefix = bytes.fromhex("302a300506032b6570032100")
    for name, digest in (
        ("controller-access.spki", CONTROLLER_SHA),
        ("identity/node-public.spki", NODE_SHA),
    ):
        blob = owned_file(ROOT / name, 100)
        if (len(blob) != 44 or not blob.startswith(prefix) or
                hashlib.sha256(blob).hexdigest() != digest):
            deny("controller_or_node_identity_untrusted")
    # The code is copied to a root-only, controlled path by our installer.
    owned_file(HANDLER, 75000)


def active(unit: str) -> bool:
    try:
        p = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit],
                           capture_output=True, timeout=7, check=False)
    except (OSError, subprocess.TimeoutExpired):
        deny("systemd_status_unavailable")
    return p.returncode == 0


def approved_peer_runtime() -> bool:
    suffix = "@fi-test-01.service"
    return (active("mnebyvpn-nodekit-awg" + suffix) and
            active("mnebyvpn-nodekit-awg-watchdog" + suffix))


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryDenied("Duplicate JSON key")
        result[key] = value
    return result


def read_command(data: bytes, now: float) -> dict:
    if not data or len(data) > MAX_COMMAND or not data.endswith(b"\n"):
        deny("invalid_command_frame")
    try:
        req = json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError):
        deny("invalid_command_json")
    if not isinstance(req, dict) or set(req) != FIELDS:
        deny("untrusted_command_fields")
    # Validate with the EXACT staged production verifier, never a parallel
    # implementation that could inadvertently accept broader commands.
    import awg_peer_grants as grant
    grant.validate_command(req, "fi-test-01", now)
    grant.verify_signature(req, ROOT / "controller-access.spki")
    return req


def handle(data: bytes, *, now: float | None = None) -> str:
    import time
    if os.geteuid() != 0:
        deny("root_required")
    check_identity()
    if data == PREFLIGHT:
        # Read-only, isolated transport proof: no client grants or services.
        if approved_peer_runtime():
            return "FI_AWG_FORCED_SSH_PREFLIGHT=trusted_channel;AWG_RUNTIME=active\n"
        return "FI_AWG_FORCED_SSH_PREFLIGHT=trusted_channel;AWG_RUNTIME=inactive\n"
    # No arbitrary command execution, even if SSH_ORIGINAL_COMMAND contains
    # shell syntax. The forced command only interprets one signed JSON frame.
    read_command(data, time.time() if now is None else now)
    if not approved_peer_runtime():
        deny("awg_or_watchdog_inactive")
    with tempfile.TemporaryDirectory(prefix="fi-awg-apply-", dir="/run") as tmp:
        command = Path(tmp) / "command.json"
        command.write_bytes(data)
        command.chmod(0o600)
        try:
            p = subprocess.run([
                "/usr/bin/python3", str(HANDLER),
                "--node-id", "fi-test-01", "--mode", "apply",
                "--command", str(command),
            ], capture_output=True, text=True, timeout=35, check=False)
        except (OSError, subprocess.TimeoutExpired):
            deny("nodekit_apply_unavailable")
    if p.returncode != 0 or len(p.stdout) > 16384:
        # Never forward the original request, private keys or stderr to SSH.
        deny("nodekit_apply_failed")
    try:
        response = json.loads(p.stdout)
        if (not isinstance(response, dict) or
                response.get("signed_command_verified") is not True or
                response.get("active") is not True or
                not isinstance(response.get("node_receipt"), dict)):
            deny("nodekit_receipt_missing")
    except ValueError:
        deny("nodekit_receipt_invalid")
    return json.dumps(response, separators=(",", ":"), sort_keys=True) + "\n"


def main() -> None:
    if sys.argv[1:]:
        deny("unexpected_handler_arguments")
    data = sys.stdin.buffer.read(MAX_COMMAND + 1)
    sys.stdout.write(handle(data))


if __name__ == "__main__":
    try:
        main()
    except (DeliveryDenied, OSError, ValueError, TypeError, RuntimeError):
        raise SystemExit(2)
