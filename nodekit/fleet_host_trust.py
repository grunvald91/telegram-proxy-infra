#!/usr/bin/env python3
"""RU188-only, noninteractive TOFU host-key registry for immutable fleet nodes.

A newly observed SSH key is not independent proof of VPS identity. This
explicitly opt-in first-contact mode pins the first Ed25519 key BEFORE any
password is sent to a node. Later host-key/IP changes fail closed.
The registrar and subscriber publication are NOT authorized by this tool.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys

ROOT = Path("/root/mnebyvpn-controller/fleet-ssh-host-keys")
CONTROLLER = "188.120.254.223"
PROTECTED = {CONTROLLER, "89.125.90.101"}
COUNTRY = re.compile(r"[a-z]{2}\Z")
NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")


class TrustError(ValueError):
    pass


def public_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError, TypeError) as exc:
        raise TrustError("Invalid target IPv4") from exc
    if str(address) != value or not address.is_global or value in PROTECTED:
        raise TrustError("Non-public or protected fleet target")
    return value


def check_identity(country: str, node: str, ip: str) -> None:
    if not COUNTRY.fullmatch(country) or not NODE.fullmatch(node) or node.endswith("-"):
        raise TrustError("Invalid immutable fleet identifier")
    public_ipv4(ip)


def canonical_key(line: str, ip: str) -> str:
    parts = line.strip().split()
    if len(parts) != 3 or parts[0] != ip or parts[1] != "ssh-ed25519":
        raise TrustError("Not the expected Ed25519 SSH key for the reviewed IPv4")
    encoded = parts[2]
    if not B64.fullmatch(encoded):
        raise TrustError("Noncanonical SSH key encoding")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TrustError("Invalid SSH host key") from exc
    if (len(raw) != 51 or raw[:4] != struct.pack(">I", 11) or
            raw[4:15] != b"ssh-ed25519" or
            raw[15:19] != struct.pack(">I", 32) or
            base64.b64encode(raw).decode() != encoded):
        raise TrustError("Malformed SSH Ed25519 key")
    return f"{ip} ssh-ed25519 {encoded}\n"


def _private_directory(path: Path) -> None:
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
        raise TrustError("Controller directory is not root-only")


def check_controller() -> None:
    if os.geteuid() != 0:
        raise TrustError("Controller root required")
    # Refuse accidental execution on FI, DE89, Actions, or an agent laptop.
    # Use the same kernel IPv4 interface check as the reviewed RU188 installer;
    # do not assume the optional iproute2 binary exists on the host.
    assigned = False
    for _, name in socket.if_nameindex():
        if len(name.encode()) > 15:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            try:
                data = fcntl.ioctl(channel.fileno(), 0x8915,
                                   struct.pack("256s", name.encode()))
                if socket.inet_ntoa(data[20:24]) == CONTROLLER:
                    assigned = True
                    break
            except OSError:
                pass
    if not assigned:
        raise TrustError("Existing RU188 assigned IPv4 required")
    _private_directory(Path("/root"))
    _private_directory(ROOT.parent)


def _create_store(root: Path) -> None:
    # Concurrent first arrivals for different countries may create the same root.
    # exist_ok is safe here because the following lstat rejects symlinks and
    # permissions that would permit another user to influence the registry.
    root.mkdir(mode=0o700, exist_ok=True)
    _private_directory(root)


def _read_pin(path: Path, ip: str) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_size > 256 or meta.st_size < 60 or
                meta.st_nlink != 1):
            raise TrustError("Unsafe stored fleet host key")
        raw = os.read(fd, 257)
        if len(raw) != meta.st_size:
            raise TrustError("Changed stored fleet host key")
        return canonical_key(raw.decode("ascii"), ip)
    finally:
        os.close(fd)


def discover(ip: str) -> str:
    result = subprocess.run(
        ["/usr/bin/ssh-keyscan", "-T", "7", "-t", "ed25519", ip],
        capture_output=True, text=True, timeout=12, check=False,
    )
    rows = [canonical_key(s, ip) for s in result.stdout.splitlines()
            if s.strip() and not s.startswith("#")]
    if len(rows) != 1:
        raise TrustError("Expected exactly one consistent SSH Ed25519 key")
    return rows[0]


def ensure_pin(country: str, node: str, ip: str, *, root: Path = ROOT,
               probe=discover, expected_key_b64: str | None = None) -> tuple[str, bool]:
    check_identity(country, node, ip)
    # An approved/provider-furnished public key is stronger than TOFU.
    # Validate and compare it BEFORE committing anything to disk.
    expected = (canonical_key(f"{ip} ssh-ed25519 {expected_key_b64}", ip)
                if expected_key_b64 is not None else None)
    _create_store(root)
    # Serialize the entire check/create operation across concurrent runners.
    lock = root / ".fleet-host-trust.lock"
    lock_fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        meta = os.fstat(lock_fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            raise TrustError("Unsafe controller trust lock")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        dest = root / f"{country}-{node}.known_hosts"
        if dest.exists() or dest.is_symlink():
            stored = _read_pin(dest, ip)
            if expected is not None and stored != expected:
                raise TrustError("Existing host pin differs from provider/owner key")
            return stored, False
        value = canonical_key(probe(ip), ip)
        if expected is not None and value != expected:
            raise TrustError("First contact differs from approved public host key")
        fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(value.encode("ascii"))
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        return value, True
    finally:
        os.close(lock_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--country", required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--expected-key-b64")
    args = parser.parse_args()
    try:
        check_controller()
        value, created = ensure_pin(args.country, args.node_id, args.ip,
                                    expected_key_b64=args.expected_key_b64 or None)
        # stdout is a single known_hosts line; no private material.
        sys.stdout.write(value)
        print("fleet_ssh_first_contact=" + ("pinned" if created else "existing"),
              file=sys.stderr)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError) as exc:
        print("FLEET_SSH_TRUST_STOPPED=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
