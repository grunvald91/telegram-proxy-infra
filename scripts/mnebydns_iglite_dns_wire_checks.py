#!/usr/bin/env python3
"""Actual DNS-over-TLS answers for one exact Instagram Lite name.

No network access at import time. Checks real A/AAAA/HTTPS/SVCB/CNAME answers,
not merely CoreDNS renderer syntax or a matching IP byte sequence.
"""
from __future__ import annotations

import secrets
import socket
import ssl
import struct

HOST = "iglite-z.instagram.com"
EDGE = "89.125.90.101"
DOT_SNI = "dns.mnebyvpn.site"
QTYPES = {"A": 1, "AAAA": 28, "HTTPS": 65, "SVCB": 64, "CNAME": 5}


def wire_name(name: str) -> bytes:
    pieces = name.rstrip(".").split(".")
    if not pieces or any(not x or len(x) > 63 for x in pieces):
        raise ValueError("invalid DNS qname")
    return b"".join(bytes([len(x)]) + x.encode("ascii") for x in pieces) + b"\x00"


def read_name(msg: bytes, start: int) -> tuple[str, int]:
    """Follow RFC 1035 compression with strict bounds/cycle guards."""
    labels = []
    at = start
    out_end = None
    visited = set()
    for _ in range(128):
        if at in visited or at >= len(msg):
            raise ValueError("DNS compression cycle / truncated name")
        visited.add(at)
        b = msg[at]
        if b & 0xC0 == 0xC0:
            if at + 1 >= len(msg):
                raise ValueError("truncated compression pointer")
            ptr = ((b & 0x3F) << 8) | msg[at + 1]
            if ptr >= len(msg):
                raise ValueError("compression pointer out of range")
            if out_end is None:
                out_end = at + 2
            at = ptr
            continue
        if b & 0xC0 or b > 63:
            raise ValueError("invalid DNS name label")
        at += 1
        if b == 0:
            return ".".join(labels).lower() + ".", at if out_end is None else out_end
        if at + b > len(msg):
            raise ValueError("truncated DNS name")
        try:
            labels.append(msg[at:at+b].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII DNS name") from exc
        at += b
    raise ValueError("DNS name too deep")


def make_question(qtype: int, transaction_id: int, host: str = HOST) -> bytes:
    return (struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
            + wire_name(host) + struct.pack("!HH", qtype, 1))


def check_answer(packet: bytes, transaction_id: int, qtype: int, host: str = HOST) -> str:
    """Require exact question and no alternate usable addresses or aliases."""
    if len(packet) < 12:
        raise ValueError("truncated DNS header")
    tid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet)
    if tid != transaction_id or not (flags & 0x8000) or (flags & 0xF):
        raise ValueError("wrong DNS response/RCODE")
    if flags & 0x0200:
        raise ValueError("truncated DNS response")
    if qd != 1 or an > 16 or ns > 16 or ar > 16:
        raise ValueError("invalid DNS sections")
    pos = 12
    name, pos = read_name(packet, pos)
    if pos + 4 > len(packet):
        raise ValueError("missing DNS question type")
    qt, cls = struct.unpack_from("!HH", packet, pos)
    pos += 4
    if name != host + "." or qt != qtype or cls != 1:
        raise ValueError("DNS question mismatch")
    answers = []
    for _ in range(an):
        owner, pos = read_name(packet, pos)
        if pos + 10 > len(packet):
            raise ValueError("truncated DNS RR header")
        kind, klass, ttl, size = struct.unpack_from("!HHIH", packet, pos)
        pos += 10
        if size > len(packet) - pos:
            raise ValueError("truncated DNS RR data")
        value = packet[pos:pos + size]
        pos += size
        # Every answer RR for exact owner is evaluated. A CNAME, HTTPS
        # service binding or AAAA can evade routing through EDGE.
        answers.append((owner, kind, klass, value))
    if qtype == QTYPES["A"]:
        if len(answers) != 1:
            raise ValueError("A response must contain one exact edge RR")
        owner, kind, klass, value = answers[0]
        if owner != host + "." or kind != 1 or klass != 1 or len(value) != 4:
            raise ValueError("unexpected A alias / answer record")
        if socket.inet_ntoa(value) != EDGE:
            raise ValueError("A did not resolve to DE edge")
        return "A_EXACT_DE"
    if answers:
        raise ValueError("non-A DNS type returned records that could bypass edge")
    return "NO_ALIAS_OR_IPV6"


def read_exact_dot_type(qtype: int, *, timeout: float = 5, host: str = HOST) -> str:
    tid = secrets.randbelow(65536)
    question = make_question(qtype, tid, host)

    def recvall(tls, length):
        data = bytearray()
        while len(data) < length:
            frag = tls.recv(length - len(data))
            if not frag:
                raise ConnectionError("premature DoT EOF")
            data.extend(frag)
        return bytes(data)

    with socket.create_connection((EDGE, 853), timeout=timeout) as plain:
        plain.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(plain, server_hostname=DOT_SNI) as tls:
            tls.sendall(struct.pack("!H", len(question)) + question)
            header = recvall(tls, 2)
            size = struct.unpack("!H", header)[0]
            if size > 4096:
                raise ValueError("unexpectedly large DoT response")
            return check_answer(recvall(tls, size), tid, qtype, host)


def check_exact_types(host: str = HOST) -> dict[str, str]:
    checks = {}
    for name, kind in QTYPES.items():
        checks[name] = read_exact_dot_type(kind, host=host)
    return checks
