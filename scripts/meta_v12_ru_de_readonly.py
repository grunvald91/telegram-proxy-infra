#!/usr/bin/env python3
"""Meta RU/DE/DoT path inventory. Intentionally read-only; NO deploy, nft or config writes.

Run only with a fixed role: external, ru, de. Reports aggregate service
states and certificate-verified TLS results, never packet payload or peer IP.
All TLS probes originate from the selected runner/server, NOT an Android phone.
"""
from __future__ import annotations
import datetime
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time

DE_PUBLIC = "89.125.90.101"
DE_WG = "10.66.77.1"
RU_PUBLIC = "188.120.254.223"
DOT_HOST = "dns.mnebyvpn.site"
NAMES = ("i.instagram.com", "iglite-z.instagram.com", "www.youtube.com", "claude.ai")

def emit(key: str, value: object) -> None:
    print(str(key) + "=" + str(value), flush=True)

def invoke(args: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=7)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 255, ""

def cert_tls(target: str, hostname: str) -> str:
    try:
        with socket.create_connection((target, 443), timeout=6) as conn:
            conn.settimeout(6)
            with ssl.create_default_context().wrap_socket(conn, server_hostname=hostname) as tls:
                return "verified_" + str(tls.version()).replace(".", "_")
    except (OSError, ssl.SSLError) as exc:
        return type(exc).__name__

def recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        block = sock.recv(n - len(out))
        if not block:
            raise EOFError("truncated DoT response")
        out.extend(block)
    return bytes(out)

def skip_name(data: bytes, offset: int) -> int:
    visited = set()
    end = None
    for _ in range(128):
        if offset in visited or offset >= len(data):
            raise ValueError("malformed name")
        visited.add(offset)
        byte = data[offset]
        if byte & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated compression pointer")
            next_offset = ((byte & 0x3F) << 8) | data[offset + 1]
            if next_offset >= len(data):
                raise ValueError("invalid compression pointer")
            if end is None:
                end = offset + 2
            offset = next_offset
            continue
        if byte & 0xC0:
            raise ValueError("invalid label")
        offset += 1
        if byte == 0:
            return end if end is not None else offset
        if offset + byte > len(data):
            raise ValueError("truncated label")
        offset += byte
    raise ValueError("too many labels")

def dot_query(name: str, qtype: int) -> str:
    qid = secrets.randbelow(65536)
    question = (b"".join(bytes([len(label)]) + label.encode("ascii")
                        for label in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1))
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question
    with socket.create_connection((DE_PUBLIC, 853), timeout=6) as raw:
        raw.settimeout(6)
        with ssl.create_default_context().wrap_socket(raw, server_hostname=DOT_HOST) as tls:
            tls.sendall(struct.pack("!H", len(msg)) + msg)
            length = struct.unpack("!H", recv_exact(tls, 2))[0]
            response = recv_exact(tls, length)
    if len(response) < 12:
        raise ValueError("truncated DNS header")
    rid, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", response)
    if rid != qid or not flags & 0x8000 or qd != 1 or flags & 0x0200:
        raise ValueError("invalid DNS header")
    position = skip_name(response, 12)
    if position + 4 > len(response) or response[position:position + 4] != struct.pack("!HH", qtype, 1):
        raise ValueError("wrong DNS question")
    position += 4
    counts = {"A_DE": 0, "A_RU": 0, "A_OTHER": 0, "AAAA": 0, "CNAME": 0, "HTTPS": 0, "SVCB": 0}
    for _ in range(an):
        position = skip_name(response, position)
        if position + 10 > len(response):
            raise ValueError("truncated RR header")
        kind, klass, _ttl, size = struct.unpack_from("!HHIH", response, position)
        position += 10
        if size > len(response) - position:
            raise ValueError("truncated RR body")
        value = response[position:position + size]
        position += size
        if klass != 1:
            continue
        if kind == 1 and size == 4:
            address = socket.inet_ntoa(value)
            counts["A_DE" if address == DE_PUBLIC else "A_RU" if address == RU_PUBLIC else "A_OTHER"] += 1
        elif kind == 28:
            counts["AAAA"] += 1
        elif kind == 5:
            counts["CNAME"] += 1
        elif kind == 65:
            counts["HTTPS"] += 1
        elif kind == 64:
            counts["SVCB"] += 1
    return "RCODE" + str(flags & 15) + "_" + "_".join(k + str(v) for k, v in counts.items())

def ports(role: str) -> None:
    for family, command in (("tcp", ["ss", "-H", "-ltn"]), ("udp", ["ss", "-H", "-lun"])):
        code, out = invoke(command)
        for port in (443, 853, 19444):
            found = bool(re.search(r":" + str(port) + r"(?:\s|$)", out))
            emit(role + "_listener_" + family + "_" + str(port), "yes" if code == 0 and found else "no_or_unknown")

def host_inventory(role: str) -> None:
    code, line = invoke(["ip", "-o", "link", "show", "dev", "tg-relay"])
    match = re.search(r"\bmtu\s+(\d+)", line)
    emit(role + "_wg_mtu", match.group(1) if code == 0 and match else "unknown")
    code, data = invoke(["wg", "show", "tg-relay", "latest-handshakes"])
    ages = []
    for line in data.splitlines():
        words = line.split()
        if len(words) == 2 and words[1].isdigit() and int(words[1]) > 0:
            ages.append(int(time.time()) - int(words[1]))
    emit(role + "_wg_handshake_age_s", min(ages) if code == 0 and ages else "none_or_unknown")
    code, _ = invoke(["nginx", "-t"])
    emit(role + "_nginx_syntax", "ok" if code == 0 else "error_or_missing")
    for unit in ("nginx", "mnebydns-dot", "wg-quick@tg-relay"):
        code, _ = invoke(["systemctl", "is-active", "--quiet", unit + ".service"])
        emit(role + "_active_" + unit.replace("@", "_").replace("-", "_"), "yes" if code == 0 else "no")
    ports(role)

def run(role: str) -> None:
    emit("observation_utc", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    emit("origin", role + "_not_mobile_isp")
    if role == "external":
        for host in NAMES:
            for qtype, label in ((1, "A"), (28, "AAAA"), (65, "HTTPS")):
                try:
                    result = dot_query(host, qtype)
                except Exception as exc:
                    result = type(exc).__name__
                emit("external_dot_" + label + "_" + host.replace(".", "_"), result)
        return
    host_inventory(role)
    if role == "ru":
        for host in ("i.instagram.com", "iglite-z.instagram.com", "claude.ai"):
            emit("ru_to_de_public_" + host.replace(".", "_"), cert_tls(DE_PUBLIC, host))
            emit("ru_to_de_wg_" + host.replace(".", "_"), cert_tls(DE_WG, host))
    elif role == "de":
        for host in ("i.instagram.com", "iglite-z.instagram.com", "claude.ai"):
            emit("de_local_ingress_" + host.replace(".", "_"), cert_tls("127.0.0.1", host))
            emit("de_to_origin_" + host.replace(".", "_"), cert_tls(host, host))

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("external", "ru", "de"):
        raise SystemExit("usage: meta_v12_ru_de_readonly.py external|ru|de")
    run(sys.argv[1])
