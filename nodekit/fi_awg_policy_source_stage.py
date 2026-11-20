#!/usr/bin/env python3
"""FI217 immutable production-policy code stage; never switch or start a service."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

NODE = "fi-test-01"
IP = "217.11.167.91"
UNIT = "mnebyvpn-nodekit-awg@fi-test-01.service"
STAGED_NODE = Path("/var/lib/mnebyvpn-nodekit/fi-test-01/manifest.json")
APP = Path("/opt/mnebyvpn-nodekit")
RELEASE_NAME = "fi-awg-production-policy-1c500093"
LOCK = Path("/run/lock/mnebyvpn-fi-awg-policy-stage.lock")
# Independently pinned Git blob IDs of the reviewed, merged PR #381.
PINS = {
    "awg_lifecycle.py": "c58d54c0f636645ef1bdedb351d97f9224c79e83",
    "install_components.py": "68d9c578c7690a05fbc9c6024176261762e37896",
    "fi_awg_production_policy.py": "c31ae46df590713a0daf26f79f3bc4916961c22a",
}

class Blocked(ValueError):
    pass

def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def checked_dir(path: Path, *, private: bool) -> None:
    if path.is_symlink() or not path.is_dir():
        raise Blocked("directory unavailable")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & (0o077 if private else 0o022):
        raise Blocked("directory not root-controlled")

def checked_file(path: Path, *, private: bool = False, limit: int = 200000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise Blocked("file unavailable")
    s = path.stat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
            s.st_mode & (0o077 if private else 0o022) or
            s.st_nlink != 1 or not 1 <= s.st_size <= limit):
        raise Blocked("file not root-controlled")
    return path.read_bytes()

def pinned_sources(source: Path) -> dict[str, bytes]:
    checked_dir(source, private=True)
    found = {}
    for name, pin in PINS.items():
        data = checked_file(source / name)
        if git_blob_id(data) != pin:
            raise Blocked("unreviewed source")
        found[name] = data
    return found

def verify_release(release: Path) -> None:
    checked_dir(release, private=True)
    if {p.name for p in release.iterdir()} != set(PINS):
        raise Blocked("unexpected release contents")
    for name, pin in PINS.items():
        data = checked_file(release / name, private=True)
        if git_blob_id(data) != pin:
            raise Blocked("release drift")

def status_of(property_name: str) -> str:
    proc = subprocess.run(
        ["/usr/bin/systemctl", "show", "-P", property_name, UNIT],
        check=False, capture_output=True, text=True, timeout=12)
    if proc.returncode:
        raise Blocked("systemd unavailable")
    return proc.stdout.strip()

def live_guard() -> None:
    if os.geteuid() != 0:
        raise Blocked("root required")
    addr = subprocess.run(
        ["/usr/sbin/ip", "-o", "-4", "addr", "show"],
        capture_output=True, text=True, check=True, timeout=12).stdout
    if not re.search(r"(?:^|\s)" + re.escape(IP) + r"/[0-9]{1,2}(?:\s|$)", addr):
        raise Blocked("unexpected host")
    document = json.loads(checked_file(STAGED_NODE, private=True, limit=16000))
    if (not isinstance(document, dict) or document.get("node_id") != NODE or
            document.get("advertise_host") != "fi.mnebyvpn.site" or
            document.get("state") != "testing" or
            document.get("activation_enabled") is not False or
            document.get("registration_enabled") is not False):
        raise Blocked("production/canary state changed")
    if (status_of("ActiveState") != "inactive" or
            status_of("UnitFileState") not in ("disabled", "static") or
            Path("/sys/class/net/awg0").exists()):
        raise Blocked("AWG is active or release-ready")
    checked_dir(APP, private=False)

def stage_payloads(payloads: dict[str, bytes], releases: Path) -> str:
    """Only write a new immutable directory, never modify an installed file."""
    checked_dir(releases, private=False)
    release = releases / RELEASE_NAME
    if release.exists() or release.is_symlink():
        verify_release(release)
        return "ALREADY_PRESENT"
    scratch = Path(tempfile.mkdtemp(prefix=".fi-awg-policy-", dir=releases))
    try:
        os.chmod(scratch, 0o700)
        for name, pin in PINS.items():
            data = payloads[name]
            if git_blob_id(data) != pin:
                raise Blocked("staged payload drift")
            target = scratch / name
            with target.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        directory = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        verify_release(scratch)
        os.rename(scratch, release)
        directory = os.open(releases, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)
    verify_release(release)
    return "STAGED"

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("stage", "verify"), required=True)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "stage" and args.source is None:
            raise Blocked("source missing")
        live_guard()
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            s = os.fstat(fd)
            if (s.st_uid != 0 or not stat.S_ISREG(s.st_mode) or
                    stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1):
                raise Blocked("unsafe lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            release_root = APP / "releases"
            if not release_root.exists():
                release_root.mkdir(mode=0o755)
            checked_dir(release_root, private=False)
            if args.mode == "stage":
                result = stage_payloads(pinned_sources(args.source), release_root)
            else:
                verify_release(release_root / RELEASE_NAME)
                result = "VERIFIED"
            live_guard()
            print("FI_AWG_POLICY_SOURCE=" + result +
                  ";UNIT_ACTIVE=false;CUSTOMER_RELEASE_UNCHANGED=true;CODE_SWITCHED=false")
            return 0
        finally:
            os.close(fd)
    except (Blocked, OSError, ValueError, KeyError, TypeError,
            json.JSONDecodeError, subprocess.SubprocessError) as error:
        print("FI_AWG_POLICY_SOURCE=BLOCKED;CODE_SWITCHED=false", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
