#!/usr/bin/env python3
"""Idempotent FI217 AWG forced-SSH transport bootstrap; no AWG activation.

controller-stage: RU188 generates its own dedicated root-only Ed25519 SSH key
and clones the EXISTING independently pinned FI host into a dedicated file.
public: RU188 returns only its AWG SSH PUBLIC key to protected runner memory.
node-stage: FI217 installs a forced-command-only authorized_keys entry and the
reviewed handler using the already pinned GitHub Actions password transport.
probe: RU188 tests real forced SSH preflight and rejects an invalid request.

Never sends private keys off RU188, updates the live AWG peer ledger, starts
AWG/watchdog, creates subscriptions, or touches PostgreSQL.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile

RU = "188.120.254.223"
FI = "217.11.167.91"
ROOT = Path("/root/mnebyvpn-controller")
NODE = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
FI_HOST = "fi.mnebyvpn.site"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
PRIVATE = ROOT / "awg-delivery-ssh"
PUBLIC = ROOT / "awg-delivery-ssh.pub"
PIN = ROOT / "awg-delivery-known_hosts"
HANDLER_PATH = Path("/opt/mnebyvpn-nodekit/fi_awg_delivery_ssh.py")
AUTH_KEYS = Path("/root/.ssh/authorized_keys")
FORCED = 'restrict,command="/usr/bin/python3 /opt/mnebyvpn-nodekit/fi_awg_delivery_ssh.py"'
NODE_COMMENT = "nodekit-awg-fi217"
PREFLIGHT = "MNEBYVPN_AWG_DELIVERY_PREFLIGHT_V1\n"


class StageBlocked(ValueError):
    pass


def block(label: str) -> None:
    print("FI_AWG_SSH_STAGE_BLOCKED=" + label, file=sys.stderr)
    raise StageBlocked(label)


def assigned(ip: str) -> bool:
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                raw = fcntl.ioctl(sock.fileno(), 0x8915,
                                  struct.pack("256s", name.encode()))
                if socket.inet_ntoa(raw[20:24]) == ip:
                    return True
            except OSError:
                pass
    return False


def trusted_dir(path: Path, *, private: bool = True) -> None:
    for folder in (path, *path.parents):
        try:
            s = folder.lstat()
        except OSError:
            block("missing_protected_directory")
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or
                s.st_mode & 0o022 or (private and folder == path and s.st_mode & 0o077)):
            block("unsafe_protected_directory")


def protected(path: Path, bound: int = 8192) -> bytes:
    # The root-owned application directory may be 0755; unlike secrets, its
    # reviewed executable must not require a private (0700) parent on rerun.
    trusted_dir(path.parent, private=path.parent != HANDLER_PATH.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        block("protected_file_missing")
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
                s.st_mode & 0o077 or s.st_nlink != 1 or
                not 1 <= s.st_size <= bound):
            block("unsafe_protected_file")
        blob = os.read(fd, bound + 1)
        if len(blob) != s.st_size:
            block("protected_file_changed")
        return blob
    finally:
        os.close(fd)


def spki(path: Path, digest: str) -> None:
    data = protected(path, 100)
    if (len(data) != 44 or not data.startswith(
            bytes.fromhex("302a300506032b6570032100")) or
            hashlib.sha256(data).hexdigest() != digest):
        block("untrusted_pinned_ed25519_identity")


def ssh_public(data: bytes) -> tuple[str, str]:
    try:
        parts = data.strip().decode("ascii").split()
    except UnicodeDecodeError:
        block("malformed_controller_ssh_public_key")
    if (len(parts) != 3 or parts[0] != "ssh-ed25519" or
            parts[2] != "mnebyvpn-fi217-awg-delivery" or
            not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", parts[1])):
        block("unapproved_ssh_public_key")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error):
        block("invalid_ssh_public_key_encoding")
    if (len(decoded) != 51 or not decoded.startswith(
            b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20") or
            base64.b64encode(decoded).decode() != parts[1]):
        block("invalid_ssh_ed25519_public_key")
    return parts[1], " ".join(parts)


def exact_pin() -> bytes:
    data = protected(ROOT / "fi-known_hosts", 512)
    parts = data.strip().decode("ascii").split()
    if len(parts) != 3 or parts[0] != FI_HOST or parts[1] != "ssh-ed25519":
        block("fi_host_pin_not_approved")
    try:
        raw = base64.b64decode(parts[2], validate=True)
    except (ValueError, base64.binascii.Error):
        block("invalid_fi_host_pin")
    if len(raw) != 51 or not raw.startswith(b"\x00\x00\x00\x0bssh-ed25519"):
        block("invalid_fi_host_key")
    return (FI_HOST + " ssh-ed25519 " + parts[2] + "\n").encode("ascii")


def atomic_new(path: Path, content: bytes) -> None:
    trusted_dir(path.parent, private=path.parent != HANDLER_PATH.parent)
    if path.exists() or path.is_symlink():
        if protected(path, max(1024, len(content) + 128)) != content:
            block("unapproved_existing_asset_change")
        return
    fd, tmp = tempfile.mkstemp(prefix=".fi-awg-stage-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Never overwrite a file that appeared after the check.
        if path.exists() or path.is_symlink():
            block("concurrent_asset_creation")
        os.link(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(tmp).unlink(missing_ok=True)


def active(unit: str) -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", unit],
                              timeout=7, capture_output=True).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        block("systemd_unavailable")


def controller_ready() -> None:
    if not assigned(RU):
        block("not_existing_ru188_root")
    trusted_dir(ROOT)
    spki(ROOT / "controller-public.spki", CONTROLLER_SHA)
    spki(ROOT / "fi-node-public.spki", NODE_SHA)
    protected(ROOT / "fi-enrollment-ssh")
    protected(ROOT / "config/fi-enrollment.env")
    if protected(ROOT / "fi-known_hosts", 512) != exact_pin():
        block("fi_host_pin_not_canonical")
    if active("mnebyvpn-awg-delivery.service"):
        block("awg_delivery_worker_already_running")


def controller_stage() -> None:
    controller_ready()
    lock = ROOT / "awg-delivery-stage.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            block("unsafe_stage_lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        atomic_new(PIN, exact_pin())
        if PRIVATE.exists() != PUBLIC.exists() or PRIVATE.is_symlink() or PUBLIC.is_symlink():
            block("incomplete_controller_key_pair")
        if not PRIVATE.exists():
            try:
                result = subprocess.run([
                    "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-a", "64",
                    "-N", "", "-C", "mnebyvpn-fi217-awg-delivery",
                    "-f", str(PRIVATE),
                ], capture_output=True, timeout=18, check=False)
            except (OSError, subprocess.TimeoutExpired):
                block("ssh_key_generation_unavailable")
            if result.returncode:
                block("ssh_key_generation_failed")
            os.chmod(PRIVATE, 0o600)
            os.chmod(PUBLIC, 0o600)
        private = protected(PRIVATE)
        public = protected(PUBLIC)
        if b"OPENSSH PRIVATE KEY" not in private:
            # PEM armoring for OpenSSH keys includes this fixed marker.
            block("invalid_openssh_private_key")
        key_body, _ = ssh_public(public)
        try:
            actual = subprocess.run(
                ["/usr/bin/ssh-keygen", "-y", "-f", str(PRIVATE)],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            block("controller_ssh_key_check_unavailable")
        if actual.returncode or actual.stdout.split()[:2] != ["ssh-ed25519", key_body]:
            block("controller_ssh_key_pair_mismatch")
        enrollment_key = subprocess.run(
            ["/usr/bin/ssh-keygen", "-y", "-f", str(ROOT / "fi-enrollment-ssh")],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if (enrollment_key.returncode or
                enrollment_key.stdout.split()[:2] == ["ssh-ed25519", key_body]):
            block("awg_ssh_key_not_independent_from_enrollment")
        print("FI_AWG_RU_SSH_KEY=dedicated_root_only;HOST_PIN=existing_approved;WORKER_STARTED=false")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def public() -> None:
    controller_ready()
    _, canonical = ssh_public(protected(PUBLIC))
    protected(PRIVATE)
    if protected(PIN, 512) != exact_pin():
        block("fi_awg_host_pin_changed")
    print(canonical)


def node_ready() -> None:
    if not assigned(FI):
        block("not_existing_fi217_root")
    trusted_dir(NODE)
    spki(NODE / "identity/node-public.spki", NODE_SHA)
    spki(NODE / "controller-access.spki", CONTROLLER_SHA)
    if (active("mnebyvpn-nodekit-awg@fi-test-01.service") or
            active("mnebyvpn-nodekit-awg-watchdog@fi-test-01.service")):
        block("refuse_authentication_stage_during_active_awg")
    manifest = __import__("json").loads(protected(NODE / "manifest.json", 10000))
    if (manifest.get("node_id") != "fi-test-01" or
            manifest.get("advertise_host") != FI_HOST or
            manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            manifest.get("activation_enabled") is not False):
        block("fi_node_not_unpublished_testing")


def node_stage(public_file: Path, handler_source: Path, sha: str) -> None:
    node_ready()
    if not re.fullmatch(r"[a-f0-9]{64}", sha or ""):
        block("unapproved_handler_sha256")
    key, _ = ssh_public(protected(public_file, 512))
    source = protected(handler_source, 16000)
    if hashlib.sha256(source).hexdigest() != sha:
        block("handler_source_sha256_mismatch")
    trusted_dir(HANDLER_PATH.parent, private=False)
    lock = AUTH_KEYS.parent / ".fi-awg-delivery-stage.lock"
    trusted_dir(AUTH_KEYS.parent)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            block("unsafe_ssh_auth_stage_lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Install the handler BEFORE authorizing its restricted SSH key.
        atomic_new(HANDLER_PATH, source)
        entry = (FORCED + " ssh-ed25519 " + key + " " + NODE_COMMENT + "\n").encode()
        if AUTH_KEYS.exists() or AUTH_KEYS.is_symlink():
            existing = protected(AUTH_KEYS, 131072)
        else:
            existing = b""
        if b"\x00" in existing or b"\r" in existing:
            block("untrusted_authorized_keys_data")
        all_lines = existing.splitlines()
        same_key = [line for line in all_lines if key.encode() in line.split()]
        same_comment = [line for line in all_lines if NODE_COMMENT.encode() in line.split()]
        if same_key or same_comment:
            if same_key != [entry.rstrip(b"\n")] or same_comment != [entry.rstrip(b"\n")]:
                block("unsafe_existing_awg_authorized_key")
            print("FI_AWG_NODE_SSH=restricted_forced_command;IDEMPOTENT=true;AWG_RUNNING=false")
            return
        if len(existing) + len(entry) + 1 > 131072:
            block("authorized_keys_capacity_exceeded")
        # The existing customer/root SSH entries are preserved byte-for-byte.
        merged = existing + (b"\n" if existing and not existing.endswith(b"\n") else b"") + entry
        temp_fd, temp = tempfile.mkstemp(prefix=".fi-awg-auth-", dir=AUTH_KEYS.parent)
        try:
            os.fchmod(temp_fd, 0o600)
            with os.fdopen(temp_fd, "wb") as output:
                output.write(merged)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp, AUTH_KEYS)
            directory = os.open(AUTH_KEYS.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temp).unlink(missing_ok=True)
        print("FI_AWG_NODE_SSH=restricted_forced_command;IDEMPOTENT=false;AWG_RUNNING=false")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def probe() -> None:
    controller_ready()
    protected(PRIVATE)
    if protected(PIN, 512) != exact_pin():
        block("fi_host_pin_mismatch")
    options = [
        "/usr/bin/ssh", "-F", "/dev/null", "-T",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "UserKnownHostsFile=" + str(PIN),
        "-o", "HostKeyAlias=" + FI_HOST, "-o", "HostName=" + FI,
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
        "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no", "-o", "ProxyCommand=none",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=8",
        "-i", str(PRIVATE), "root@" + FI_HOST, "false",
    ]
    try:
        yes = subprocess.run(options, input=PREFLIGHT, capture_output=True,
                             text=True, check=False, timeout=20)
        no = subprocess.run(options, input="{}\n", capture_output=True,
                            text=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        block("forced_ssh_transport_unreachable")
    if (yes.returncode or yes.stdout.strip() !=
            "FI_AWG_FORCED_SSH_PREFLIGHT=trusted_channel;AWG_RUNTIME=inactive"):
        block("forced_ssh_readonly_preflight_failed")
    if no.returncode == 0 or no.stdout.strip():
        block("forced_ssh_invalid_payload_was_not_rejected")
    print("FI_AWG_FORCED_SSH=verified;INVALID_JSON=denied;AWG_STARTED=false;CLIENTS_PUBLISHED=false")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("controller-stage", "public", "node-stage", "probe"),
                        required=True)
    parser.add_argument("--public-file", type=Path)
    parser.add_argument("--handler-source", type=Path)
    parser.add_argument("--handler-sha256")
    args = parser.parse_args()
    if args.mode == "node-stage":
        if not args.public_file or not args.handler_source or not args.handler_sha256:
            block("node_stage_input_missing")
        node_stage(args.public_file, args.handler_source, args.handler_sha256)
    else:
        if args.public_file or args.handler_source or args.handler_sha256:
            block("unapproved_controller_bootstrap_arguments")
        {"controller-stage": controller_stage, "public": public, "probe": probe}[args.mode]()


if __name__ == "__main__":
    try:
        main()
    except (StageBlocked, OSError, ValueError, TypeError, UnicodeError,
            subprocess.SubprocessError, KeyError, AttributeError):
        raise SystemExit(2)
