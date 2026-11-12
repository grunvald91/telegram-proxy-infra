#!/usr/bin/env python3
"""Read-only external evidence for MNEBYDNS routes and TLS passthrough.

No remote mutations, client identifiers, credentials in output, or automatic
route changes. Only the legacy monitored routes are asserted as working.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

Route = Literal["proxy", "direct", "observe"]


@dataclass(frozen=True)
class Service:
    name: str
    hostname: str
    route: Route
    tls_observe: bool = False


# "observe" is not a claim of support or grounds for changing live routes.
SERVICES = (
    Service("gemini", "gemini.google.com", "proxy", True),
    Service("claude_web", "claude.ai", "proxy", True),
    Service("claude_api", "api.anthropic.com", "proxy", True),
    Service("grok", "grok.com", "proxy", True),
    Service("x_api", "api.x.ai", "proxy", True),
    Service("x", "x.com", "proxy", True),
    Service("tiktok_web", "www.tiktok.com", "proxy", True),
    Service("tiktok_api", "api.tiktokv.com", "proxy", True),
    Service("instagram", "www.instagram.com", "observe", True),
    Service("instagram_api", "i.instagram.com", "observe", True),
    Service("threads", "threads.net", "observe", True),
    Service("microsoft", "copilot.microsoft.com", "observe", True),
    Service("ordinary_web", "example.org", "direct"),
    Service("ordinary_telegram", "api.telegram.org", "direct"),
)


@dataclass(frozen=True)
class DnsAnswer:
    rcode: int
    addresses: tuple[str, ...]


def _fqdn(name: str) -> bytes:
    labels = name.rstrip(".").encode("idna").split(b".")
    if not labels or any(not part or len(part) > 63 for part in labels):
        raise ValueError("invalid DNS name")
    return b"".join(bytes([len(part)]) + part for part in labels) + b"\x00"


def _read_exact(sock: ssl.SSLSocket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError("short DNS/TLS frame")
        data.extend(part)
    return bytes(data)


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    consumed = None
    seen: set[int] = set()
    for _ in range(128):
        if offset >= len(message) or offset in seen:
            raise ValueError("invalid DNS compression pointer")
        seen.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("short compression pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if consumed is None:
                consumed = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), offset if consumed is None else consumed
        if offset + length > len(message):
            raise ValueError("truncated DNS label")
        labels.append(message[offset:offset+length].decode("ascii"))
        offset += length
    raise ValueError("too many DNS labels")


def decode_dns_response(packet: bytes, qname: str, qtype: int, transaction: int) -> DnsAnswer:
    if len(packet) < 12:
        raise ValueError("short DNS response")
    txid, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", packet)
    if txid != transaction or not flags & 0x8000 or qd != 1:
        raise ValueError("invalid DNS response header")
    name, offset = _read_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("short DNS question")
    requested_type, qclass = struct.unpack_from("!HH", packet, offset)
    if name != qname.rstrip(".").lower() or requested_type != qtype or qclass != 1:
        raise ValueError("DNS question mismatch")
    offset += 4
    ips: list[str] = []
    for _ in range(an):
        _, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS record")
        typ, cls, _, n = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + n > len(packet):
            raise ValueError("truncated DNS RDATA")
        if cls == 1 and typ == qtype and n == (4 if qtype == 1 else 16):
            ips.append(str(ipaddress.ip_address(packet[offset:offset+n])))
        offset += n
    return DnsAnswer(flags & 0x0F, tuple(ips))


def dot_query(resolver_ip: str, tls_name: str, host: str, qtype: int, timeout: float = 5) -> DnsAnswer:
    ipaddress.ip_address(resolver_ip)
    transaction = int.from_bytes(os.urandom(2), "big")
    question = _fqdn(host) + struct.pack("!HH", qtype, 1)
    payload = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    with socket.create_connection((resolver_ip, 853), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=tls_name) as tls:
            tls.sendall(struct.pack("!H", len(payload)) + payload)
            n = struct.unpack("!H", _read_exact(tls, 2))[0]
            if n > 16384:
                raise ValueError("unexpectedly large DNS reply")
            return decode_dns_response(_read_exact(tls, n), host, qtype, transaction)


def verified_tls_handshake(ip: str, hostname: str, timeout: float = 5) -> float:
    ipaddress.ip_address(ip)
    started = time.monotonic()
    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls:
            if not tls.version():
                raise ssl.SSLError("no negotiated TLS protocol")
    return round((time.monotonic() - started) * 1000, 1)


def evaluate_route(expected: Route, answer: DnsAnswer, ingress: str) -> str:
    if answer.rcode != 0 or not answer.addresses:
        return "fail" if expected != "observe" else "unknown"
    if expected == "proxy":
        return "pass" if set(answer.addresses) == {ingress} else "fail"
    if expected == "direct":
        return "pass" if ingress not in answer.addresses else "fail"
    return "observe_proxy" if ingress in answer.addresses else "observe_direct"


def monitor(
    resolver_ip: str,
    resolver_sni: str,
    ingress_ip: str,
    egress: str,
    *,
    query: Callable[[str, int], DnsAnswer] | None = None,
    tls_probe: Callable[[str, str], float] | None = None,
    services: tuple[Service, ...] = SERVICES,
) -> dict:
    ipaddress.ip_address(ingress_ip)
    if egress not in {"match", "mismatch", "unknown"}:
        raise ValueError("egress must be match, mismatch or unknown")
    query = query or (lambda host, qtype: dot_query(resolver_ip, resolver_sni, host, qtype))
    tls_probe = tls_probe or verified_tls_handshake
    records = []
    failures = 0
    for service in services:
        started = time.monotonic()
        try:
            answer = query(service.hostname, 1)
            dns = evaluate_route(service.route, answer, ingress_ip)
            route_observation = "ingress" if ingress_ip in answer.addresses else "origin_or_other"
            err = None
        except (OSError, ValueError, EOFError, ssl.SSLError) as exc:
            dns, route_observation, err = (
                "fail" if service.route != "observe" else "unknown"
            ), "unknown", type(exc).__name__
        if dns == "fail":
            failures += 1
        record = {
            "service": service.name,
            "expected": service.route,
            "dns": dns,
            "route_observed": route_observation,
            "dns_ms": round((time.monotonic() - started) * 1000, 1),
            "dns_error_class": err,
            "ipv6": "unknown",
            "tls": "not_checked",
            "tls_ms": None,
        }
        # An AAAA response can bypass an IPv4-only rewrite. Observe but don't
        # claim a verified client leak without an actual client-network test.
        try:
            aaaa = query(service.hostname, 28)
            if aaaa.rcode != 0:
                record["ipv6"] = "dns_error"
            elif aaaa.addresses and service.route == "proxy":
                record["ipv6"] = "possible_direct_bypass"
            else:
                record["ipv6"] = "present" if aaaa.addresses else "absent"
        except (OSError, ValueError, EOFError, ssl.SSLError):
            record["ipv6"] = "unknown"
        # Only test SNI against ingress if DNS actually selects the ingress.
        if service.tls_observe and route_observation == "ingress":
            try:
                record["tls_ms"] = tls_probe(ingress_ip, service.hostname)
                record["tls"] = "pass"
            except (OSError, ValueError, EOFError, ssl.SSLError) as exc:
                record["tls"] = "fail"
                record["tls_error_class"] = type(exc).__name__
            # TLS is observational, NOT a client/app availability gate yet.
        records.append(record)
    if egress == "mismatch":
        failures += 1
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "vantage": "github_runner_external_not_end_user",
        "egress_ip": egress,
        "critical_failures": failures,
        "route_fallback_enabled": False,
        "services": records,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--resolver-ip", required=True)
    p.add_argument("--resolver-sni", required=True)
    p.add_argument("--ingress-ip", required=True)
    p.add_argument("--egress", choices=("match", "mismatch", "unknown"), default="unknown")
    p.add_argument("--output", default="health.json")
    args = p.parse_args()
    report = monitor(args.resolver_ip, args.resolver_sni, args.ingress_ip, args.egress)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    for item in report["services"]:
        print(f"service={item['service']} dns={item['dns']} ipv6={item['ipv6']} tls={item['tls']} ms={item['dns_ms']}")
    print(f"egress_stability={report['egress_ip']} critical_failures={report['critical_failures']}")
    if (summary := os.environ.get("GITHUB_STEP_SUMMARY")):
        with open(summary, "a", encoding="utf8") as f:
            f.write("### Read-only MNEBYDNS health\n\n")
            f.write(f"DNS route regressions/egress mismatch: **{report['critical_failures']}**. "
                    "No automatic failover or route changes. TLS is observational.\n\n")
            f.write("| Service | DNS route | IPv6 | TLS | DNS ms |\n|---|---|---|---|---:|\n")
            for item in report["services"]:
                f.write(f"| {item['service']} | {item['dns']} | {item['ipv6']} | {item['tls']} | {item['dns_ms']} |\n")
    return 1 if report["critical_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
