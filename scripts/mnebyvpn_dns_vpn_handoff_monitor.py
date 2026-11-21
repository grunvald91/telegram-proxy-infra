#!/usr/bin/env python3
"""Read-only MNEBYVPN DNS/VPN compatibility probe.

Two vantages: runner (outside VPN), owner (existing DE89 Xray UID, whose
local OUTPUT/853 redirect is different from remote PREROUTING/853).
No real subscriber identifiers, no service mutations and no client E2E claim.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import time

IP = "89.125.90.101"
LEGACY = "dns.mnebyvpn.site"
TIMEOUT = 4.0
MAX_DNS_FRAME = 8192


def frame(txid: int) -> tuple[bytes, bytes]:
    name = b"\x07example\x03org\x00"
    question = name + struct.pack("!HH", 1, 1)
    message = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    return struct.pack("!H", len(message)) + message, question


def exact(sock, length: int) -> bytes:
    if length < 0 or length > MAX_DNS_FRAME:
        raise ValueError("invalid_dns_length")
    parts = bytearray()
    while len(parts) < length:
        chunk = sock.recv(length - len(parts))
        if not chunk:
            raise EOFError("short_dns_stream")
        parts.extend(chunk)
    return bytes(parts)


def check_dns(sock, txid: int, question: bytes) -> None:
    answer_len = struct.unpack("!H", exact(sock, 2))[0]
    if answer_len < 12 + len(question) or answer_len > MAX_DNS_FRAME:
        raise ValueError("invalid_dns_length")
    answer = exact(sock, answer_len)
    reply_id, flags, qd, _, _, _ = struct.unpack_from("!HHHHHH", answer)
    if (reply_id != txid or not (flags & 0x8000) or
            flags & 0x7800 or qd != 1 or
            answer[12:12 + len(question)] != question):
        raise ValueError("invalid_dns_reply")
    if (flags & 0xF) != 0:
        raise ValueError("dns_rcode_" + str(flags & 0xF))


def classify_error(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, EOFError):
        return "closed"
    if isinstance(exc, ValueError):
        reason = str(exc)
        if reason in ("invalid_dns_reply", "invalid_dns_length") or reason.startswith("dns_rcode_"):
            return reason
    return "network_or_protocol"


def single(sni: str, dns: bool) -> dict:
    started = time.monotonic()
    phase = "tcp"
    try:
        with socket.create_connection((IP, 853), timeout=TIMEOUT) as plain:
            plain.settimeout(TIMEOUT)
            phase = "tls"
            with ssl.create_default_context().wrap_socket(plain, server_hostname=sni) as conn:
                conn.settimeout(TIMEOUT)
                if dns:
                    phase = "dns"
                    txid = secrets.randbelow(65536)
                    message, question = frame(txid)
                    conn.sendall(message)
                    check_dns(conn, txid, question)
        return {"ok": True, "phase": "done", "ms": round((time.monotonic() - started) * 1000)}
    except (OSError, ValueError, EOFError) as exc:
        return {"ok": False, "phase": phase, "error": classify_error(exc),
                "ms": round((time.monotonic() - started) * 1000)}


def verdict(series: list[dict]) -> str:
    if not series:
        return "UNKNOWN"
    for field in ("legacy_dns", "personal_tls"):
        failures = sum(not x[field]["ok"] for x in series)
        if failures >= 2:
            return "FAIL"
    if any(not x[field]["ok"] for x in series for field in ("legacy_dns", "personal_tls")):
        return "DEGRADED"
    return "PASS"


def run(vantage: str, samples: int, delay: float) -> dict:
    series = []
    for i in range(samples):
        # TLS validation uses a never-issued identity; it cannot verify
        # authenticated personal DNS queries, so do not report that as PASS.
        random_sni = secrets.token_hex(6) + ".dns.mnebyvpn.site"
        series.append({
            "legacy_dns": single(LEGACY, True),
            "personal_tls": single(random_sni, False),
        })
        if i + 1 < samples:
            time.sleep(delay)
    state = verdict(series)
    return {
        "schema": 1, "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "vantage": vantage, "state": state, "samples": samples, "checks": series,
        "client_wifi_transition_verified": False,
        "client_vpn_tunnel_verified": False,
        "authenticated_personal_dns_verified": False,
        "production_mutations": False,
    }


def selftest() -> None:
    msg, question = frame(0x1234)
    answer = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0) + question
    class Stub:
        def __init__(self, data): self.data = data
        def recv(self, n):
            head, self.data = self.data[:min(n, 3)], self.data[min(n, 3):]
            return head
    check_dns(Stub(struct.pack("!H", len(answer)) + answer), 0x1234, question)
    try:
        check_dns(Stub(struct.pack("!H", len(answer)) + answer), 0x1235, question)
    except ValueError as ex:
        assert str(ex) == "invalid_dns_reply"
    else:
        raise AssertionError("mismatched transaction accepted")
    assert msg[:2] == struct.pack("!H", len(msg) - 2)
    a = {"legacy_dns": {"ok": True}, "personal_tls": {"ok": True}}
    b = {"legacy_dns": {"ok": False}, "personal_tls": {"ok": True}}
    c = {"legacy_dns": {"ok": True}, "personal_tls": {"ok": False}}
    assert verdict([a, a, a]) == "PASS"
    assert verdict([a, b, a]) == "DEGRADED"
    assert verdict([a, b, b]) == "FAIL"
    assert verdict([a, c, c]) == "FAIL"
    assert verdict([]) == "UNKNOWN"
    print("DNS_VPN_COMPAT_SELFTEST=PASS")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--vantage", choices=("runner", "vpn-owner"), default="runner")
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--delay", type=float, default=2.0)
    p.add_argument("--output")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        selftest()
        return 0
    if not 1 <= a.samples <= 5 or not 0 <= a.delay <= 12:
        p.error("unsafe probe count or delay")
    result = run(a.vantage, a.samples, a.delay)
    serialized = json.dumps(result, separators=(",", ":"), sort_keys=True)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as output:
            output.write(serialized + "\n")
    print(serialized, flush=True)
    return 1 if result["state"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
