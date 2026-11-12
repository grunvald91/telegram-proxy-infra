#!/usr/bin/env python3
"""Read-only public transport/DoT reachability audit.

No SSH credentials, no DNS changes, no TLS bypass, no packet payload logging.
Designed for GitHub-hosted runner, NOT an Android/mobile ISP test.
"""
from __future__ import annotations
import socket
import ssl
import struct
import time

DOT_HOST = "dns.mnebyvpn.site"
RU = "188.120.254.223"
DE = "89.125.90.101"
HOSTS = ("i.instagram.com", "graph.instagram.com", "www.threads.com",
         "gemini.google.com", "claude.ai")
TCP = ((RU, 22), (RU, 80), (RU, 443), (RU, 18443), (DE, 443), (DE, 853))


def tcp_probe(host: str, port: int):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=4):
            return "CONNECTED", round((time.monotonic() - start) * 1000)
    except (OSError, TimeoutError) as e:
        # Public runner cannot unambiguously identify an ISP, firewall or TSPU.
        return type(e).__name__, round((time.monotonic() - start) * 1000)


def encode_query(host: str, qtype: int, ident: int):
    name = b"".join(bytes((len(p),)) + p.encode("ascii") for p in host.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)


def read_exact(sock, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            raise ConnectionError("DoT socket closed before response")
        result.extend(part)
    return bytes(result)


def skip_dns_name(data: bytes, start: int):
    at = start
    for _ in range(128):
        if at >= len(data):
            raise ValueError("Invalid truncated name")
        first = data[at]
        if first & 0xC0 == 0xC0:
            if at + 2 > len(data):
                raise ValueError("Truncated DNS pointer")
            return at + 2
        if first & 0xC0:
            raise ValueError("Invalid label")
        at += 1
        if first == 0:
            return at
        at += first
    raise ValueError("DNS name too long")


def decode_a(data: bytes, expected_ident: int):
    if len(data) < 12:
        raise ValueError("Short DNS response")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data)
    if ident != expected_ident or not flags & 0x8000:
        raise ValueError("Mismatched response id or missing DNS response bit")
    rcode = flags & 0x0F
    at = 12
    for _ in range(qd):
        at = skip_dns_name(data, at) + 4
        if at > len(data):
            raise ValueError("Truncated question")
    ips = []
    for _ in range(an):
        at = skip_dns_name(data, at)
        if at + 10 > len(data):
            raise ValueError("Truncated answer")
        typ, cls, _ttl, size = struct.unpack_from("!HHIH", data, at)
        at += 10
        if at + size > len(data):
            raise ValueError("Truncated RDATA")
        if typ == 1 and cls == 1 and size == 4:
            ips.append(socket.inet_ntoa(data[at:at + 4]))
        at += size
    return rcode, ips


def dot_query(tls, host: str, ident: int):
    question = encode_query(host, 1, ident)
    tls.sendall(struct.pack("!H", len(question)) + question)
    size = struct.unpack("!H", read_exact(tls, 2))[0]
    if size < 12 or size > 65535:
        raise ValueError("Invalid DNS response size")
    return decode_a(read_exact(tls, size), ident)


def main():
    print("public_probe_source=github_actions_runner")
    print("test_scope=external_connectivity_not_android_or_operator")
    for server, port in TCP:
        status, elapsed = tcp_probe(server, port)
        print(f"tcp_{server.replace('.', '_')}_{port}={status};elapsed_ms={elapsed}", flush=True)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((DOT_HOST, 853), timeout=7) as raw:
            raw.settimeout(7)
            with context.wrap_socket(raw, server_hostname=DOT_HOST) as tls:
                print("dot_tls_certificate_verified=true")
                for i, host in enumerate(HOSTS, 1):
                    try:
                        rcode, ips = dot_query(tls, host, 0xA000 + i)
                        routing = ("RU" if RU in ips else "DE" if DE in ips
                                   else "DIRECT_OR_OTHER" if ips else "NO_A_RESPONSE")
                        print(f"dot_{host}=rcode:{rcode};route:{routing};a_count:{len(ips)}")
                    except Exception as e:
                        print(f"dot_{host}=QUERY_ERROR:{type(e).__name__}")
                        raise
    except Exception as exc:
        print(f"dot_tls_probe=FAIL:{type(exc).__name__}", flush=True)
        raise
    print("public_field_readiness_measurement=COMPLETE")
    print("android_instagram_e2e=NOT_TESTED")


if __name__ == "__main__":
    main()
