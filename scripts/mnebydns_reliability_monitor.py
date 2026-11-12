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
    # TCP DNS responses must not be truncated, must be standard replies
    # and must contain precisely the question we issued. Never interpret a
    # copied or unrelated A/AAAA RR as proof that a route is correct.
    if (txid != transaction or not flags & 0x8000 or flags & 0x7A00
            or qd != 1):
        raise ValueError("invalid DNS response header")
    name, offset = _read_name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("short DNS question")
    requested_type, qclass = struct.unpack_from("!HH", packet, offset)
    if name != qname.rstrip(".").lower() or requested_type != qtype or qclass != 1:
        raise ValueError("DNS question mismatch")
    offset += 4
    aliases: dict[str, str] = {}
    candidates: list[tuple[str, str]] = []
    for _ in range(an):
        owner, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS record")
        typ, cls, _, n = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if offset + n > len(packet):
            raise ValueError("truncated DNS RDATA")
        if cls == 1 and typ == 5:
            target, end = _read_name(packet, offset)
            if end != offset + n or not target:
                raise ValueError("invalid CNAME RDATA")
            if owner in aliases and aliases[owner] != target:
                raise ValueError("conflicting CNAME aliases")
            aliases[owner] = target
        elif cls == 1 and typ == qtype and n == (4 if qtype == 1 else 16):
            candidates.append((owner, str(ipaddress.ip_address(packet[offset:offset+n]))))
        offset += n

    valid_owners = {name}
    cursor = name
    for _ in range(16):
        target = aliases.get(cursor)
        if target is None:
            break
        if target in valid_owners:
            raise ValueError("CNAME cycle in DNS response")
        valid_owners.add(target)
        cursor = target
    else:
        raise ValueError("CNAME chain exceeded limit")
    return DnsAnswer(flags & 0x0F, tuple(ip for owner, ip in candidates if owner in valid_owners))


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


def tcp_reachable(host: str, *, timeout: float = 4, attempts: int = 2) -> tuple[str, str | None]:
    """External TCP/443 evidence via IPv4, with a bounded retry.

    One GitHub runner probe is not a client reachability SLA. Probe only;
    never change a server, firewall, DNS or VPN route in response.
    """
    if not 1 <= attempts <= 3:
        raise ValueError("attempts out of range")
    last_error = None
    for index in range(attempts):
        try:
            # Restrict both targets to AF_INET for a comparable control.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(timeout)
                conn.connect((host, 443))
            return "pass", None
        except (OSError, ValueError) as exc:
            last_error = type(exc).__name__
            if index + 1 < attempts:
                time.sleep(0.15)
    return "fail", last_error


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
    ingress_tcp: str = "unknown",
    control_tcp: str = "unknown",
    ingress_tcp_error: str | None = None,
) -> dict:
    ipaddress.ip_address(ingress_ip)
    if ingress_tcp not in {"pass", "fail", "unknown"} or control_tcp not in {"pass", "fail", "unknown"}:
        raise ValueError("invalid TCP probe state")
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
        if service.tls_observe and route_observation == "ingress" and ingress_tcp == "fail":
            record["tls"] = "skipped_ingress_tcp_unreachable"
        elif service.tls_observe and route_observation == "ingress":
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
    # Probe TCP/443 from the same external runner to an ordinary control host.
    # Public 443 on the foreign host is a separate, unverified route:
    # actual customers may use RU/WG/private paths. A GitHub-runner timeout
    # cannot be promoted to a confirmed client outage or a hard CI failure.
    external_tcp_path_warning = ingress_tcp == "fail" and control_tcp == "pass"
    transport_warning_count = sum(
        item["tls"] in {"fail", "skipped_ingress_tcp_unreachable"} for item in records
    )
    ipv6_possible_bypass_count = sum(
        item["ipv6"] == "possible_direct_bypass" for item in records
    )
    diagnostics_incomplete = (
        bool(transport_warning_count) or ingress_tcp != "pass"
        or control_tcp != "pass" or egress == "unknown"
        or bool(ipv6_possible_bypass_count)
    )
    health_classification = (
        "dns_or_node_egress_regression" if failures
        else "dns_routes_observed_transport_unverified" if diagnostics_incomplete
        else "dns_routes_and_public_transport_observed"
    )
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "vantage": "github_runner_external_not_end_user",
        "egress_ip": egress,
        "tcp_ingress": ingress_tcp,
        "tcp_control": control_tcp,
        "tcp_error_class": ingress_tcp_error,
        "external_tcp_path_warning": external_tcp_path_warning,
        "transport_warning_count": transport_warning_count,
        "ipv6_possible_bypass_count": ipv6_possible_bypass_count,
        "health_classification": health_classification,
        "client_end_to_end_verified": False,
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
    ingress_state, ingress_error = tcp_reachable(args.ingress_ip)
    control_state, _ = tcp_reachable("example.org")
    report = monitor(args.resolver_ip, args.resolver_sni, args.ingress_ip, args.egress,
                     ingress_tcp=ingress_state, control_tcp=control_state,
                     ingress_tcp_error=ingress_error)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    for item in report["services"]:
        print(f"service={item['service']} dns={item['dns']} ipv6={item['ipv6']} tls={item['tls']} ms={item['dns_ms']}")
    print(f"egress_stability={report['egress_ip']} tcp_ingress={report['tcp_ingress']} "
          f"tcp_control={report['tcp_control']} tcp_error_class={report['tcp_error_class']} "
          f"transport_warnings={report['transport_warning_count']} "
          f"external_path_warning={report['external_tcp_path_warning']} "
          f"health={report['health_classification']} "
          f"critical_failures={report['critical_failures']}")
    if report["transport_warning_count"] or report["external_tcp_path_warning"]:
        print("::warning title=SmartDNS transport unverified::Public ingress TCP/TLS checks failed "
              "or were skipped; this does not prove an outage on the client data path")
    if report["ipv6_possible_bypass_count"]:
        print("::warning title=SmartDNS IPv6 route risk::Some proxied hosts return AAAA records "
              "that could bypass IPv4-only routing; real-client validation is required")
    if report["egress_ip"] == "unknown":
        print("::warning title=SmartDNS direct egress unknown::Node public IPv4 was not verified")
    if (summary := os.environ.get("GITHUB_STEP_SUMMARY")):
        with open(summary, "a", encoding="utf8") as f:
            f.write("### Read-only MNEBYDNS health\n\n")
            f.write(f"DNS and node direct-egress regressions: **{report['critical_failures']}**. "
                    f"Public ingress TCP: **{report['tcp_ingress']}**, control TCP: **{report['tcp_control']}**, "
                    f"TLS warnings: **{report['transport_warning_count']}**. "
                    f"Classification: **{report['health_classification']}**. "
                    "Real-client E2E: **NOT VERIFIED**. "
                    "No automatic failover or route changes.\n\n")
            f.write("| Service | DNS route | IPv6 | TLS | DNS ms |\n|---|---|---|---|---:|\n")
            for item in report["services"]:
                f.write(f"| {item['service']} | {item['dns']} | {item['ipv6']} | {item['tls']} | {item['dns_ms']} |\n")
    return 1 if report["critical_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
