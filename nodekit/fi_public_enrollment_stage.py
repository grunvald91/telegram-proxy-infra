#!/usr/bin/env python3
"""FI/RU188 public-only enrollment staging, NOT runtime access authorization.

Copy only controller PUBLIC Ed25519 SPKI and dedicated enrollment SSH PUBLIC
key, pin FI node identity + SSH host at RU188, install FI-only forced command.
No private key ever leaves its origin. Does not change DB, firewall, network
listeners, AWG peers, customer subscriptions, or any live handshake.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import tempfile

NODE_ID = "fi-test-01"
FI_IP = "217.11.167.91"
RU_IP = "188.120.254.223"
FI_HOST = "fi.mnebyvpn.site"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
KEY_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")


class StageError(ValueError):
    pass


def check_host(expected: str) -> None:
    if os.geteuid() != 0:
        raise StageError("Root required")
    assigned = False
    for _, name in socket.if_nameindex():
        if len(name.encode()) > 15:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            try:
                raw = fcntl.ioctl(channel.fileno(), 0x8915,
                                  struct.pack("256s", name.encode()))
                if socket.inet_ntoa(raw[20:24]) == expected:
                    assigned = True
                    break
            except OSError:
                pass
    if not assigned:
        raise StageError("Enrollment stage attempted on the wrong VPS")


def protected_dir(path: Path, *, private: bool = True, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700 if private else 0o755, exist_ok=True)
    meta = path.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or
            meta.st_mode & (0o077 if private else 0o022)):
        raise StageError("Unsafe root-owned enrollment directory")


def protected_read(path: Path, max_bytes: int = 4096) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_mode & 0o077 or meta.st_nlink != 1 or
                not 1 <= meta.st_size <= max_bytes):
            raise StageError("Unsafe public enrollment input or output")
        data = os.read(fd, max_bytes + 1)
        if len(data) != meta.st_size:
            raise StageError("Enrollment file changed while reading")
        return data
    finally:
        os.close(fd)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verified_spki(data: bytes, expected_sha: str) -> bytes:
    if (len(data) != 44 or not data.startswith(ED25519_SPKI) or
            sha(data) != expected_sha):
        raise StageError("Pinned Ed25519 public SPKI mismatch")
    return data


def parse_ssh_pub(raw: bytes) -> str:
    fields = raw.decode("ascii").strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise StageError("Dedicated enrollment SSH key is not Ed25519")
    b64 = fields[1]
    if not KEY_RE.fullmatch(b64):
        raise StageError("Invalid enrollment SSH public key encoding")
    try:
        binary = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StageError("Malformed enrollment SSH public key") from exc
    if (len(binary) != 51 or binary[:15] !=
            struct.pack(">I", 11) + b"ssh-ed25519" or
            binary[15:19] != struct.pack(">I", 32) or
            base64.b64encode(binary).decode() != b64):
        raise StageError("Invalid enrollment SSH public-key structure")
    return b64


def parse_pinned_fi_host(raw: bytes) -> str:
    words = raw.decode("ascii").strip().split()
    if len(words) != 3 or words[0] != FI_IP or words[1] != "ssh-ed25519":
        raise StageError("FI SSH host pin must be the stored IPv4 Ed25519 key")
    parse_ssh_pub(("ssh-ed25519 " + words[2]).encode())
    return FI_HOST + " ssh-ed25519 " + words[2] + "\n"


def write_once(path: Path, data: bytes, *, install: bool) -> None:
    if path.exists() or path.is_symlink():
        if protected_read(path, max_bytes=max(4096, len(data))) != data:
            raise StageError("Existing enrollment trust file differs")
        return
    if not install:
        raise StageError("Enrollment trust file has not been installed")
    fd, temp = tempfile.mkstemp(prefix=".fi-enrollment-public-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(temp, path, follow_symlinks=False)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(temp).unlink(missing_ok=True)


def forced_command(enrollment_key: str, node_sha: str,
                   controller_sha: str) -> bytes:
    command = (
        "/usr/bin/python3 /opt/mnebyvpn-nodekit/fi_enrollment_ssh.py"
        f" --node-id {NODE_ID} --expected-identity-sha256 {node_sha}"
        f" --expected-controller-sha256 {controller_sha}"
    )
    return (f'restrict,command="{command}" ssh-ed25519 {enrollment_key}'
            " nodekit-fi-enrollment\n").encode("ascii")


def authorized_key(ssh_dir: Path, expected: bytes, key_b64: str,
                   *, install: bool) -> None:
    protected_dir(ssh_dir, create=install)
    path = ssh_dir / "authorized_keys"
    if not install:
        # Read-only verification must never create a lock or SSH file.
        existing = protected_read(path, max_bytes=131072)
        matches = [line for line in existing.splitlines()
                   if key_b64.encode() in line.split()]
        if len(matches) != 1 or matches[0] + b"\n" != expected:
            raise StageError("Required restrictive enrollment SSH entry is missing")
        return
    lock = ssh_dir / ".fi-enrollment-stage.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        check = os.fstat(fd)
        if (not stat.S_ISREG(check.st_mode) or check.st_uid != 0 or
                check.st_mode & 0o077 or check.st_nlink != 1):
            raise StageError("Unsafe SSH authorized_keys stage lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if path.exists() or path.is_symlink():
            old = protected_read(path, max_bytes=131072)
        else:
            old = b""
        matching = [
            line for line in old.splitlines()
            if key_b64.encode() in line.split()
        ]
        if matching:
            if len(matching) != 1 or matching[0] + b"\n" != expected:
                raise StageError("Dedicated SSH enrollment key has unsafe existing rights")
            return
        if not install:
            raise StageError("Dedicated FI forced-command access is missing")
        if b"\0" in old or b"\r" in old:
            raise StageError("Malformed existing authorized_keys")
        data = old + (b"\n" if old and not old.endswith(b"\n") else b"") + expected
        if len(data) > 131072:
            raise StageError("SSH authorized_keys exceeds safe limit")
        fd_temp, temp = tempfile.mkstemp(prefix=".fi-ssh-keys-", dir=ssh_dir)
        try:
            os.fchmod(fd_temp, 0o600)
            with os.fdopen(fd_temp, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp, path)
            parent = os.open(ssh_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            Path(temp).unlink(missing_ok=True)
    finally:
        os.close(fd)


def stage_fi(node: Path, app: Path, ssh_dir: Path,
             controller_source: Path, ssh_public_source: Path,
             handler_source: Path, handler_sha: str,
             *, install: bool, node_sha: str = NODE_SHA,
             controller_sha: str = CONTROLLER_SHA) -> None:
    protected_dir(node.parent)
    protected_dir(node)
    protected_dir(node / "identity")
    manifest = json.loads(protected_read(node / "manifest.json", max_bytes=10000))
    if (manifest.get("node_id") != NODE_ID or
            manifest.get("advertise_host") != FI_HOST or
            manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            manifest.get("activation_enabled") is not False):
        raise StageError("FI Nodekit is not the expected unpublished testing VPS")
    verified_spki(protected_read(node / "identity/node-public.spki", 100), node_sha)
    controller = verified_spki(protected_read(controller_source, 100), controller_sha)
    ssh_key = parse_ssh_pub(protected_read(ssh_public_source, 512))
    handler = protected_read(handler_source, max_bytes=100000)
    if not re.fullmatch(r"[a-f0-9]{64}", handler_sha) or sha(handler) != handler_sha:
        raise StageError("Enrollment handler differs from reviewed SHA-256")
    protected_dir(app, private=False, create=install)
    # Install and verify durable code + trust material before authorizing SSH.
    write_once(app / "fi_enrollment_ssh.py", handler, install=install)
    write_once(node / "controller-access.spki", controller, install=install)
    authorized_key(ssh_dir, forced_command(ssh_key, node_sha, controller_sha),
                   ssh_key, install=install)


def stage_controller(directory: Path, fi_public: Path, fi_host_pin: Path,
                     *, install: bool, node_sha: str = NODE_SHA,
                     controller_sha: str = CONTROLLER_SHA) -> None:
    protected_dir(directory)
    verified_spki(protected_read(directory / "controller-public.spki", 100),
                  controller_sha)
    node_key = verified_spki(protected_read(fi_public, 100), node_sha)
    raw_pin = protected_read(fi_host_pin, max_bytes=256)
    stored = protected_read(
        directory / "fleet-ssh-host-keys/fi-fi-test-01.known_hosts", max_bytes=256)
    if raw_pin != stored:
        raise StageError("FI SSH host pin differs from RU188 first-contact registry")
    alias = parse_pinned_fi_host(stored).encode("ascii")
    write_once(directory / "fi-known_hosts", alias, install=install)
    write_once(directory / "fi-node-public.spki", node_key, install=install)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("fi", "controller"), required=True)
    parser.add_argument("--mode", choices=("stage", "check"), required=True)
    parser.add_argument("--controller-spki", type=Path)
    parser.add_argument("--enrollment-ssh-public", type=Path)
    parser.add_argument("--handler-source", type=Path)
    parser.add_argument("--handler-sha256")
    parser.add_argument("--fi-node-public", type=Path)
    parser.add_argument("--fi-host-pin", type=Path)
    args = parser.parse_args()
    try:
        check_host(FI_IP if args.role == "fi" else RU_IP)
        if args.role == "fi":
            if not all((args.controller_spki, args.enrollment_ssh_public,
                        args.handler_source, args.handler_sha256)):
                raise StageError("FI public-only enrollment input missing")
            stage_fi(Path("/var/lib/mnebyvpn-nodekit") / NODE_ID,
                     Path("/opt/mnebyvpn-nodekit"), Path("/root/.ssh"),
                     args.controller_spki, args.enrollment_ssh_public,
                     args.handler_source, args.handler_sha256,
                     install=args.mode == "stage")
        else:
            if not all((args.fi_node_public, args.fi_host_pin)):
                raise StageError("Controller public-only input missing")
            stage_controller(Path("/root/mnebyvpn-controller"),
                             args.fi_node_public, args.fi_host_pin,
                             install=args.mode == "stage")
        print(f"fi_public_stage_{args.role}=verified;subscribers_enabled=false;"
              "db_enrollment_started=false")
        return 0
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        print("FI_PUBLIC_ENROLLMENT_STAGE_STOPPED=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
