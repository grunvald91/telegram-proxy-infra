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

INGRESS = "188.120.254.223"
DE89_EDGE = "89.125.90.101"
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


def _skip_name(wire, offset):
    for _ in range(128):
        if offset >= len(wire):
            raise ValueError("dns_invalid_header")
        n = wire[offset]
        if n & 0xC0 == 0xC0:
            if offset + 1 >= len(wire):
                raise ValueError("dns_invalid_header")
            return offset + 2
        if n & 0xC0:
            raise ValueError("dns_invalid_header")
        if n == 0:
            return offset + 1
        offset += 1 + n
    raise ValueError("dns_invalid_header")


def read_reply(sock, txid, question):
    length = struct.unpack("!H", recv_exact(sock, 2))[0]
    if length < 12 + len(question) or length > MAX_FRAME:
        raise ValueError("dns_frame_length")
    wire = recv_exact(sock, length)
    answer_id, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", wire)
    if answer_id != txid or flags & 0x8000 == 0 or flags & 0x7800 or qd != 1:
        raise ValueError("dns_invalid_header")
    if wire[12:12 + len(question)] != question:
        raise ValueError("dns_question_mismatch")
    offset = 12 + len(question)
    ips = []
    for _ in range(an):
        offset = _skip_name(wire, offset)
        if offset + 10 > len(wire):
            raise ValueError("dns_invalid_header")
        rrtype, rrclass, _, rdlen = struct.unpack_from("!HHIH", wire, offset)
        offset += 10
        if offset + rdlen > len(wire):
            raise ValueError("dns_invalid_header")
        if rrtype == 1 and rrclass == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(wire[offset:offset + 4]))
        offset += rdlen
    return flags & 0x0F, ips


def read_answer(sock, txid, question):
    return read_reply(sock, txid, question)[0]


def probe(target=INGRESS):
    start = time.monotonic()
    phase = "tcp"
    synthetic_host = None
    try:
        with socket.create_connection((target, 853), timeout=3.5) as plain:
            plain.settimeout(3.5)
            phase = "tls"
            with ssl.create_default_context().wrap_socket(plain, server_hostname=TLS_NAME) as tls:
                tls.settimeout(3.5)
                phase = "dns"
                rcode_by_host = {}
                for host in HOSTS:
                    synthetic_host = host
                    txid = int.from_bytes(os.urandom(2), "big")
                    query, question = request_for(host, txid)
                    tls.sendall(struct.pack("!H", len(query)) + query)
                    rcode, ips = read_reply(tls, txid, question)
                    if rcode != 0:
                        raise ValueError("dns_rcode_" + str(rcode))
                    if host == "www.youtube.com" and ips != [INGRESS]:
                        raise ValueError("dns_unexpected_a")
                    if host == "example.org" and (not ips or INGRESS in ips or DE89_EDGE in ips):
                        raise ValueError("dns_unexpected_a")
                    rcode_by_host[host] = rcode
        return {"ok": True, "phase": "done", "query_count": len(rcode_by_host),
                "latency_ms": round((time.monotonic() - start) * 1000, 1)}
    except (OSError, ssl.SSLError, EOFError, ValueError, TimeoutError) as ex:
        result = {"ok": False, "phase": phase, "error_class": type(ex).__name__,
                  "latency_ms": round((time.monotonic() - start) * 1000, 1)}
        if phase == "dns":
            # Only these two hard-coded synthetic names are ever reported.
            result["synthetic_host"] = synthetic_host if synthetic_host in HOSTS else "unknown"
            if isinstance(ex, ValueError):
                reason = str(ex)
                allowed = {"dns_frame_length", "dns_invalid_header", "dns_question_mismatch", "dns_unexpected_a"}
                if reason.startswith("dns_rcode_") and reason.removeprefix("dns_rcode_").isdigit():
                    result["error_reason"] = reason
                else:
                    result["error_reason"] = reason if reason in allowed else "dns_validation_other"
        return result


def self_test():
    assert INGRESS == "188.120.254.223" and DE89_EDGE == "89.125.90.101"
    query, q = request_for("example.org", 0x1234)
    response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0) + q
    class Stub:
        def __init__(self, data): self.data = data
        def recv(self, n):
            chunk, self.data = self.data[:n], self.data[n:]
            return chunk
    assert query[:2] == b"\x12\x34"
    assert read_answer(Stub(struct.pack("!H", len(response)) + response), 0x1234, q) == 0
    _, yq = request_for("www.youtube.com", 0x2222)
    yresp = (struct.pack("!HHHHHH", 0x2222, 0x8180, 1, 1, 0, 0) + yq +
             b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 20, 4) + socket.inet_aton(INGRESS))
    assert read_reply(Stub(struct.pack("!H", len(yresp)) + yresp), 0x2222, yq) == (0, [INGRESS])
    try:
        read_answer(Stub(struct.pack("!H", len(response)) + response), 0x5678, q)
    except ValueError as exc:
        assert str(exc) == "dns_invalid_header"
    else:
        raise AssertionError("wrong DNS transaction accepted")
    servfail = struct.pack("!HHHHHH", 0x1234, 0x8182, 1, 0, 0, 0) + q
    assert read_answer(Stub(struct.pack("!H", len(servfail)) + servfail), 0x1234, q) == 2
    from unittest.mock import patch
    def run_mock(youtube_ip):
        seen = []
        class FakeTls:
            def __init__(self): self._buf = b""
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, _): pass
            def sendall(self, data):
                txid = struct.unpack("!H", data[2:4])[0]
                qwire = data[14:]
                ip_bytes = socket.inet_aton("93.184.215.14" if b"example" in qwire else youtube_ip)
                pkt = (struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + qwire +
                       b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 20, 4) + ip_bytes)
                self._buf = struct.pack("!H", len(pkt)) + pkt
            def recv(self, n):
                out, self._buf = self._buf[:n], self._buf[n:]
                return out
        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, _): pass
        class FakeCtx:
            def wrap_socket(self, _s, server_hostname):
                seen.append(("sni", server_hostname))
                return FakeTls()
        def connect(ep, timeout=3.5):
            seen.append(("connect", ep))
            return FakeSock()
        with patch.object(socket, "create_connection", side_effect=connect), \
             patch.object(ssl, "create_default_context", return_value=FakeCtx()):
            return probe(), seen
    ok_res, seen = run_mock(INGRESS)
    assert ok_res["ok"] is True and seen == [("connect", ("188.120.254.223", 853)), ("sni", "dns.mnebyvpn.site")]
    bad_res, _ = run_mock(DE89_EDGE)
    assert bad_res["ok"] is False and bad_res["error_reason"] == "dns_unexpected_a"
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
