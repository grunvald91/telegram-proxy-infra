#!/usr/bin/env python3
"""Guarded DE89 Smart DNS A-only restoration from current live CoreDNS.

Never restores databases, drops host rules, changes Nginx, deletes policies,
modifies WireGuard, or turns off RU188 DoT during public DNS propagation.
All writes are checkpoint-protected and fail closed on drift.
"""
from __future__ import annotations
import collections
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

EDGE = "89.125.90.101"
RU = "188.120.254.223"
BASE = Path("/opt/mnebydns-de89-restore-20261115")
DNS = Path("/opt/mnebydns-dot/Corefile")
NGINX = Path("/etc/nginx/nginx.conf")
PROXY = Path("/etc/mnebydns-googlepilot/nginx.conf")
PTR = Path("/opt/mnebydns-stable-checkpoints/current")
EXPECTED_OLD_SHA = "3ee64c23c17007e9cd4045df7c1fd688913638db2b48dbf0179b372e6f2841bc"
EXPECTED_A_COUNT = 564
TIMER = "mnebydns-de89-restore-revert-20261115.timer"
SCRIPT = "/usr/local/sbin/mnebydns-de89-restore-20261115.py"
A_LINE = re.compile(r'(?m)^([ \t]*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+)((?:\d{1,3}\.){3}\d{1,3})("[ \t]*)$')
A_HEADER = re.compile(r"(?m)^[ \t]*template[ \t]+IN[ \t]+A[ \t]+([^\s{]+)[ \t]*\{")
SAMPLES = ("chatgpt.com", "gemini.google.com", "www.youtube.com",
           "claude.ai", "x.com", "grok.com", "www.tiktok.com",
           "artifacts.elastic.co", "account.mongodb.com")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cmd(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=True, text=True, **kwargs)


def expected_services() -> None:
    for service in ("nginx", "mnebydns-dot.service", "mnebydns-googlepilot.service"):
        if cmd("systemctl", "is-active", service).stdout.strip() != "active":
            raise RuntimeError("SERVICE_NOT_ACTIVE_" + service)
    cmd("nginx", "-t")
    if "89.125.90.101:853" not in cmd("ss", "-Hlnt", "sport = :853").stdout:
        raise RuntimeError("DE89_DOT_LISTENER_MISSING")


def valid_checkpoint(expected_dns: bytes) -> Path:
    path = Path(PTR.read_text().strip())
    if not re.fullmatch(r"/opt/mnebydns-stable-checkpoints/[0-9]+", str(path)):
        raise RuntimeError("STABLE_POINTER_FORMAT_DRIFT")
    cmd("sha256sum", "-c", "stable-manifest.sha256", cwd=path)
    if (path / "dns.stable").read_bytes() != expected_dns:
        raise RuntimeError("STABLE_DNS_DRIFT")
    for name, remote in (("nginx.stable", NGINX), ("proxy.stable", PROXY)):
        if (path / name).read_bytes() != remote.read_bytes():
            raise RuntimeError("STABLE_OTHER_SERVICE_DRIFT")
    return path


def render(current: str) -> tuple[str, int]:
    matches = list(A_LINE.finditer(current))
    if len(matches) != EXPECTED_A_COUNT or len(A_HEADER.findall(current)) != EXPECTED_A_COUNT:
        raise RuntimeError("A_RULE_COUNT_DRIFT")
    if set(m.group(2) for m in matches) != {RU}:
        raise RuntimeError("FOREIGN_OR_MIXED_A_ANSWERS_NOT_APPROVED")
    if current.count("tls://.:853 {") != 1 or current.count("    bind 89.125.90.101") != 1:
        raise RuntimeError("CORE_DOT_STRUCTURE_DRIFT")
    replaced, n = A_LINE.subn(lambda m: m.group(1) + EDGE + m.group(3), current)
    if n != EXPECTED_A_COUNT:
        raise RuntimeError("A_EDIT_COUNT_MISMATCH")
    inverse, reverse_count = A_LINE.subn(
        lambda m: m.group(1) + RU + m.group(3), replaced)
    if inverse != current or reverse_count != n:
        raise RuntimeError("NON_A_DATA_CHANGED")
    return replaced, n


def atomic_core(content: bytes) -> None:
    original = DNS.stat()
    tmp = DNS.with_name("Corefile.de89-restore-tmp-20261115")
    if tmp.exists():
        raise RuntimeError("TEMP_FILE_EXISTS")
    try:
        tmp.write_bytes(content)
        os.chown(tmp, original.st_uid, original.st_gid)
        os.chmod(tmp, original.st_mode & 0o7777)
        os.replace(tmp, DNS)
    finally:
        tmp.unlink(missing_ok=True)


def query(address: str, host: str) -> list[str]:
    qid = os.urandom(2)
    labels = b"".join(bytes([len(x)]) + x.encode() for x in host.split(".")) + b"\x00"
    question = qid + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    with socket.create_connection((address, 853 if address != "127.0.0.1" else 18553), timeout=5) as raw:
        raw.settimeout(7)
        with ssl.create_default_context().wrap_socket(raw, server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(len(question).to_bytes(2, "big") + question)
            head = tls.recv(2)
            if len(head) != 2:
                raise RuntimeError("DOT_FRAME_MISSING")
            length = int.from_bytes(head, "big")
            if not 12 <= length <= 16384:
                raise RuntimeError("DOT_FRAME_BAD_SIZE")
            body = b""
            while len(body) < length:
                part = tls.recv(length - len(body))
                if not part:
                    raise RuntimeError("DOT_FRAME_TRUNCATED")
                body += part
    if body[:2] != qid or body[3] & 15:
        raise RuntimeError("DOT_ANSWER_FAILED_" + host)
    return [ip for ip in (EDGE, RU) if socket.inet_aton(ip) in body]


def probe(address: str) -> None:
    for host in SAMPLES:
        if query(address, host) != [EDGE]:
            raise RuntimeError("DOT_A_RETURN_NOT_DE89_" + host)
    if query(address, "example.org"):
        raise RuntimeError("DIRECT_CONTROL_REWRITTEN")
    print("RESTORE_DOT_VERIFIED_SAMPLES=" + str(len(SAMPLES)), flush=True)


def stage() -> None:
    expected_services()
    old = DNS.read_bytes()
    if sha(old) != EXPECTED_OLD_SHA:
        raise RuntimeError("LIVE_CORE_SHA_CHANGED_REAUDIT_REQUIRED")
    checkpoint = valid_checkpoint(old)
    current = old.decode()
    candidate, count = render(current)
    if BASE.exists():
        raise RuntimeError("RESTORE_ALREADY_STAGED")
    BASE.mkdir(parents=True, mode=0o700)
    (BASE / "dns.before").write_bytes(old)
    (BASE / "dns.candidate").write_bytes(candidate.encode())
    (BASE / "checkpoint.before").write_text(str(checkpoint) + "\n")
    (BASE / "sha.before").write_text(sha(old) + "\n")
    (BASE / "sha.candidate").write_text(sha(candidate.encode()) + "\n")
    for name in ("dns.before", "dns.candidate", "checkpoint.before",
                 "sha.before", "sha.candidate"):
        os.chmod(BASE / name, 0o600)
    isolated = candidate.replace("tls://.:853 {", "tls://.:18553 {", 1)
    isolated = isolated.replace("    bind 89.125.90.101", "    bind 127.0.0.1", 1)
    dry = BASE / "Corefile.isolated"
    dry.write_text(isolated)
    os.chmod(dry, 0o600)
    if "127.0.0.1:18553" in cmd("ss", "-Hlnt", "sport = :18553").stdout:
        raise RuntimeError("ISOLATED_DOT_PORT_BUSY")
    with (BASE / "preflight.log").open("wb") as log:
        child = subprocess.Popen(["/opt/mnebydns-dot/coredns", "-conf", str(dry)],
                                 stdout=log, stderr=subprocess.STDOUT)
        try:
            ready = False
            for _ in range(55):
                if child.poll() is not None:
                    raise RuntimeError("ISOLATED_COREDNS_EXITED")
                if "127.0.0.1:18553" in cmd("ss", "-Hlnt", "sport = :18553").stdout:
                    ready = True
                    break
                time.sleep(.2)
            if not ready:
                raise RuntimeError("ISOLATED_COREDNS_NOT_LISTENING")
            probe("127.0.0.1")
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
    shutil.copy2(sys.argv[0], SCRIPT)
    os.chmod(SCRIPT, 0o700)
    print("DE89_STAGE_SAFE_A_ONLY=" + str(count), flush=True)
    print("DE89_STAGE_CURRENT_SHA=" + sha(old), flush=True)
    print("DE89_STAGE_CANDIDATE_SHA=" + sha(candidate.encode()), flush=True)


def lock():
    Path("/run/lock/mnebyvpn-public-route.lock").touch(exist_ok=True)
    f = open("/run/lock/mnebyvpn-public-route.lock", "r+")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


def require_stage() -> tuple[bytes, bytes, str]:
    old = (BASE / "dns.before").read_bytes()
    new = (BASE / "dns.candidate").read_bytes()
    point = (BASE / "checkpoint.before").read_text().strip()
    if sha(old) != (BASE / "sha.before").read_text().strip():
        raise RuntimeError("BACKUP_HASH_DRIFT")
    if sha(new) != (BASE / "sha.candidate").read_text().strip():
        raise RuntimeError("CANDIDATE_HASH_DRIFT")
    if PTR.read_text().strip() != point:
        raise RuntimeError("STABLE_CHECKPOINT_MOVED")
    valid_checkpoint(old)
    return old, new, point


def apply() -> None:
    with lock():
        old, new, _ = require_stage()
        if DNS.read_bytes() != old:
            raise RuntimeError("LIVE_DNS_CHANGED_SINCE_STAGE")
        expected_services()
        cmd("systemd-run", "--quiet", "--unit=mnebydns-de89-restore-revert-20261115",
            "--on-active=30m", "--collect", "/usr/bin/python3", SCRIPT, "rollback")
        if cmd("systemctl", "is-active", TIMER).stdout.strip() != "active":
            raise RuntimeError("INDEPENDENT_ROLLBACK_NOT_ARMED")
        atomic_core(new)
        time.sleep(8)
        expected_services()
        if DNS.read_bytes() != new:
            raise RuntimeError("CANDIDATE_FILE_DRIFT")
        probe(EDGE)
        print("DE89_PRODUCTION_DOT_NOW_RETURNS_DE89=PASS", flush=True)


def rollback() -> None:
    with lock():
        old = (BASE / "dns.before").read_bytes()
        new = (BASE / "dns.candidate").read_bytes()
        point = (BASE / "checkpoint.before").read_text().strip()
        if PTR.read_text().strip() != point:
            raise RuntimeError("CONFIRMED_CHECKPOINT_REFUSES_AUTO_ROLLBACK")
        current = DNS.read_bytes()
        if current == new:
            atomic_core(old)
            time.sleep(8)
        elif current != old:
            raise RuntimeError("UNKNOWN_CORE_STATE_REFUSES_ROLLBACK")
        expected_services()
        if DNS.read_bytes() != old:
            raise RuntimeError("ROLLBACK_CONTENT_NOT_RESTORED")
        cmd("systemctl", "stop", TIMER, check=False)
        print("DE89_RESTORE_ROLLBACK_OLD_RU_A_VERIFIED=PASS", flush=True)


def finalize() -> None:
    with lock():
        old, new, point = require_stage()
        if DNS.read_bytes() != new:
            raise RuntimeError("CANDIDATE_NO_LONGER_LIVE")
        expected_services()
        if cmd("systemctl", "is-active", TIMER).stdout.strip() != "active":
            raise RuntimeError("ROLLBACK_TIMER_NOT_RUNNING")
        probe(EDGE)
        root = PTR.parent
        dest = root / str(int(time.time()))
        if dest.exists():
            raise RuntimeError("NEW_CHECKPOINT_COLLISION")
        shutil.copytree(point, dest)
        shutil.copy2(DNS, dest / "dns.stable")
        manifest = "".join(
            sha((dest / name).read_bytes()) + "  " + name + "\n"
            for name in ("nginx.stable", "dns.stable", "proxy.stable"))
        (dest / "stable-manifest.sha256").write_text(manifest)
        cmd("sha256sum", "-c", "stable-manifest.sha256", cwd=dest)
        if (dest / "dns.stable").read_bytes() != DNS.read_bytes():
            raise RuntimeError("CHECKPOINT_DNS_MISMATCH")
        tmp = PTR.with_name("current.de89-restore.tmp")
        if tmp.exists():
            raise RuntimeError("POINTER_TEMP_EXISTS")
        tmp.write_text(str(dest) + "\n")
        os.chmod(tmp, PTR.stat().st_mode & 0o7777)
        os.replace(tmp, PTR)
        (BASE / "confirmed").write_text(str(dest) + "\n")
        cmd("systemctl", "stop", TIMER, check=False)
        print("DE89_STABLE_CHECKPOINT=" + str(dest), flush=True)
        print("DE89_564_A_RULES_SWITCHED_WITHOUT_DB_CHANGE=PASS", flush=True)


if __name__ == "__main__":
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ("stage", "apply", "rollback", "finalize"):
        raise SystemExit(2)
    {"stage": stage, "apply": apply, "rollback": rollback, "finalize": finalize}[sys.argv[1]]()
