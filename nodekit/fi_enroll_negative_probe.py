#!/usr/bin/env python3
"""Read-only negative SSH forced-command probe for existing FI registration.

Sends only an intentionally invalid challenge '{}', which the dedicated FI
handler MUST reject. No private keys, valid challenges, or DB writes. Never
prints SSH stderr, credentials or public key material.
"""
import fcntl
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys

ROOT = Path("/root/mnebyvpn-controller")
RU = "188.120.254.223"
HOST = "fi.mnebyvpn.site"
IP = "217.11.167.91"


def block(reason):
    print("FI_ENROLL_NEGATIVE_PROBE_BLOCKED=" + reason, file=sys.stderr)
    raise ValueError(reason)


def on_ru188():
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                blob = fcntl.ioctl(sock.fileno(), 0x8915,
                                   struct.pack("256s", name.encode()))
                if socket.inet_ntoa(blob[20:24]) == RU:
                    return True
            except OSError:
                pass
    return False


def trusted(path):
    for root in path.parents:
        s = root.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid or s.st_mode & 0o022:
            block("trust_ancestor_invalid")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid or
                s.st_mode & 0o077 or s.st_nlink != 1 or
                not 1 <= s.st_size <= 8192):
            block("trust_asset_unprotected")
        return os.read(fd, min(s.st_size,8192)).decode("ascii","replace")
    finally:
        os.close(fd)


def forced_ssh_args():
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "UserKnownHostsFile=" + str(ROOT / "fi-known_hosts"),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
        "-o", "HostKeyAlias=" + HOST,
        "-o", "HostName=" + IP,
        "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no", "-o", "ProxyCommand=none",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=8",
        "-i", str(ROOT / "fi-enrollment-ssh"),
        "root@" + HOST, "false",
    ]


def run():
    if not on_ru188():
        block("wrong_controller")
    pinned = trusted(ROOT / "fi-known_hosts")
    if len(pinned.splitlines()) != 1 or not pinned.startswith(HOST + " ssh-ed25519 "):
        block("untrusted_host_pin")
    trusted(ROOT / "fi-enrollment-ssh")
    try:
        proc = subprocess.run(
            forced_ssh_args(), input="{}\n", text=True, capture_output=True,
            timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        block("ssh_transport_unavailable")
    # A *rejection* proves that the FI forced-command handler received the
    # bogus request; any acceptance is a serious safety violation.
    if proc.returncode == 0:
        block("unexpected_invalid_challenge_acceptance")
    if "NODEKIT_ENROLLMENT_ERROR=EnrollmentSshError" in proc.stderr:
        print("FI_FORCED_SSH_HANDLER_REACHED=true;INVALID_CHALLENGE_REJECTED=true")
        return
    if "Permission denied" in proc.stderr:
        block("dedicated_enrollment_ssh_auth_denied")
    if "Host key verification failed" in proc.stderr:
        block("fi_ssh_host_pin_failed")
    if "Connection timed out" in proc.stderr or "Connection refused" in proc.stderr:
        block("fi_ssh_transport_unreachable")
    block("fi_forced_command_handler_unverified")


if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError, UnicodeError):
        raise SystemExit(2)
