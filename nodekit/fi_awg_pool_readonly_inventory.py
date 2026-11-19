#!/usr/bin/env python3
"""FI217 root-only AWG node pool inventory (READ ONLY; no customer release).

Checks that the persistent staged AWG public key really derives from the
private key in the protected FI217 config. Never exports the private key,
opens a listener, activates a peer, or registers a PostgreSQL pool.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import socket
import stat
import struct
import fcntl
import subprocess
import sys

FI_IP = "217.11.167.91"
ROOT = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
AWG = Path("/opt/mnebyvpn-amneziawg/awg")
NODE = "fi-test-01"
PUB = re.compile(r"[A-Za-z0-9+/]{43}=\\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\\Z")


class Blocked(ValueError):
    pass


def fail() -> None:
    raise Blocked("verified AWG node pool inventory blocked")


def is_fi() -> bool:
    if __import__("os").geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                data = fcntl.ioctl(sock.fileno(), 0x8915,
                                   struct.pack("256s", name.encode()))
                if socket.inet_ntoa(data[20:24]) == FI_IP:
                    return True
        except OSError:
            continue
    return False


def protected(path: Path, maximum: int = 16000) -> bytes:
    for directory in path.parents:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
            fail()
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o077 or info.st_nlink != 1
            or not 1 <= info.st_size <= maximum):
        fail()
    fd = __import__("os").open(
        path, __import__("os").O_RDONLY | __import__("os").O_NOFOLLOW
        | __import__("os").O_CLOEXEC)
    try:
        actual = __import__("os").fstat(fd)
        if (actual.st_ino != info.st_ino or actual.st_dev != info.st_dev
                or actual.st_size != info.st_size):
            fail()
        raw = __import__("os").read(fd, maximum + 1)
        if len(raw) != info.st_size:
            fail()
        return raw
    finally:
        __import__("os").close(fd)


def stopped(unit: str) -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit],
        capture_output=True, timeout=8, check=False)
    if result.returncode == 0:
        fail()


def inspect() -> str:
    if not is_fi():
        fail()
    for unit in (
        "mnebyvpn-nodekit-awg@fi-test-01.service",
        "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
    ):
        stopped(unit)
    try:
        manifest = json.loads(protected(ROOT / "amneziawg/manifest.json", 12000))
    except (json.JSONDecodeError, UnicodeError):
        fail()
    if not isinstance(manifest, dict):
        fail()
    checks = {
        "schema_version": 1, "node_id": NODE, "protocol": "AmneziaWG 3.1",
        "state": "staged", "activation_enabled": False,
        "peers_enabled": False, "subscribers_enabled": False,
        "port": 51821, "test_address": "10.73.91.1/24",
    }
    if any(type(manifest.get(k)) is not type(v) or manifest[k] != v
           for k, v in checks.items()):
        fail()
    pub = manifest.get("server_public_key")
    digest = manifest.get("config_sha256")
    binary_hash = manifest.get("source_binary_sha256")
    if (not isinstance(pub, str) or not PUB.fullmatch(pub)
            or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
            or not isinstance(binary_hash, dict)
            or not isinstance(binary_hash.get("awg"), str)
            or not DIGEST.fullmatch(binary_hash["awg"])):
        fail()
    if len(base64.b64decode(pub, validate=True)) != 32:
        fail()
    config_bytes = protected(ROOT / "amneziawg/awg0.conf", 12000)
    if hashlib.sha256(config_bytes).hexdigest() != digest:
        fail()
    config = config_bytes.decode("ascii")
    if (config.count("[Interface]") != 1 or "[Peer]" in config
            or config.count("Address = 10.73.91.1/24") != 1
            or config.count("ListenPort = 51821") != 1):
        fail()
    private = re.findall(r"^PrivateKey = ([A-Za-z0-9+/]{43}=)$",
                         config, re.MULTILINE)
    if len(private) != 1:
        fail()
    binary_info = AWG.lstat()
    if (not stat.S_ISREG(binary_info.st_mode) or binary_info.st_uid != 0
            or binary_info.st_mode & 0o022
            or not binary_info.st_mode & stat.S_IXUSR):
        fail()
    if hashlib.sha256(AWG.read_bytes()).hexdigest() != binary_hash["awg"]:
        fail()
    result = subprocess.run(
        [str(AWG), "pubkey"], input=private[0] + "\n",
        capture_output=True, text=True, timeout=8, check=False)
    if result.returncode or result.stdout.strip() != pub:
        fail()
    # The key is public, but only its digest is reported to CI. It is not
    # a signed live egress proof and MUST NOT set the SQL 'verified' state.
    return "FI_AWG_POOL_PERSISTENT_MANIFEST=PASS;NODE=" + NODE + (
        ";SUBNET=10.73.91.0/24;PUBLIC_KEY_SHA256="
        + hashlib.sha256(base64.b64decode(pub)).hexdigest()
        + ";PRODUCTION_PROOF=false;AWG_STARTED=false;CUSTOMER_RELEASE=false"
    )


def main() -> int:
    try:
        print(inspect())
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError,
            UnicodeError, subprocess.SubprocessError):
        print("FI_AWG_POOL_PERSISTENT_MANIFEST=BLOCKED;"
              "AWG_STARTED=false;CUSTOMER_RELEASE=false")
        return 2


if __name__ == "__main__":
    sys.exit(main())
