#!/usr/bin/env python3
"""One-minute, read-only synthetic Android Private DNS (DoT) probe.

Runs on existing RU and DE hosts only. Never reads client traffic, changes
CoreDNS, restarts services, opens a listener or writes DNS configurations.
Only fixed synthetic domain names and error classes reach journald.
"""
import datetime as dt
import json
import os
import socket
import ssl
import struct
import sys
import time

EDGE = "89.125.90.101"
TLS_NAME = "dns.mnebyvpn.site"
HOSTS = ("example.org", "www.youtube.com")
MAX_FRAME = 16384


def request_for(host, txid):
    labels = host.split(".")
    if not labels or any(not x or len(x) > 63 or not x.isascii() for x in labels):
        raise ValueError("bad test name")
    name = b"".join(bytes((len(x),)) + x.encode("ascii") for x in labels) + b"\0"
    question = name + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    return query, question


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("DoT stream ended")
        data.extend(chunk)
    return bytes(data)


def read_answer(sock, txid, question):
    length = struct.unpack("!H", recv_exact(sock, 2))[0]
    if length < 12 + len(question) or length > MAX_FRAME:
        raise ValueError("invalid DNS/TLS length")
    wire = recv_exact(sock, length)
    answer_id, flags, qd, _, _, _ = struct.unpack_from("!HHHHHH", wire)
    if answer_id != txid or flags & 0x8000 == 0 or flags & 0x7800 or qd != 1:
        raise ValueError("invalid DNS/TLS response")
    if wire[12:12 + len(question)] != question:
        raise ValueError("DNS/TLS question mismatch")
    return flags & 0x0F


def probe():
    start = time.monotonic()
    phase = "tcp"
    try:
        with socket.create_connection((EDGE, 853), timeout=3.5) as plain:
            plain.settimeout(3.5)
            phase = "tls"
            with ssl.create_default_context().wrap_socket(plain, server_hostname=TLS_NAME) as tls:
                tls.settimeout(3.5)
                phase = "dns"
                rcode_by_host = {}
                for host in HOSTS:
                    txid = int.from_bytes(os.urandom(2), "big")
                    query, question = request_for(host, txid)
                    tls.sendall(struct.pack("!H", len(query)) + query)
                    rcode = read_answer(tls, txid, question)
                    if rcode != 0:
                        raise ValueError("nonzero DNS response code")
                    rcode_by_host[host] = rcode
        return {"ok": True, "phase": "done", "query_count": len(rcode_by_host),
                "latency_ms": round((time.monotonic() - start) * 1000, 1)}
    except (OSError, ssl.SSLError, EOFError, ValueError, TimeoutError) as ex:
        return {"ok": False, "phase": phase, "error_class": type(ex).__name__,
                "latency_ms": round((time.monotonic() - start) * 1000, 1)}


def self_test():
    query, q = request_for("example.org", 0x1234)
    response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0) + q
    class Stub:
        def __init__(self, data): self.data = data
        def recv(self, n):
            chunk, self.data = self.data[:n], self.data[n:]
            return chunk
    assert query[:2] == b"\x12\x34"
    assert read_answer(Stub(struct.pack("!H", len(response)) + response), 0x1234, q) == 0
    try:
        read_answer(Stub(struct.pack("!H", len(response)) + response), 0x5678, q)
    except ValueError:
        pass
    else:
        raise AssertionError("wrong DNS transaction accepted")
    print("MNEBYDNS_MINUTE_PROBE_SELF_TEST=PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) > 1:
        raise SystemExit(2)
    else:
        result = {"at_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                  "component": "dot_minute_synthetic", **probe()}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        raise SystemExit(0 if result["ok"] else 1)
