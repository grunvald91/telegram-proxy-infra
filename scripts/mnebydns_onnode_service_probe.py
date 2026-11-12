#!/usr/bin/env python3
"""Bounded, read-only local SNI/HTTP observation for one MNEBYDNS foreign VPS.

Intended to run on the EXISTING foreign node via a pinned SSH session.
Never changes routing, firewall, DNS, TLS keys or service state. This proves
neither end-user connectivity nor application login nor a per-service exit IP.
No HTTP response body, cookies, client addresses or redirects are recorded.
"""
from __future__ import annotations

import concurrent.futures
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone

# Only confirmed proxy routes. Microsoft is observed separately because its
# current routing policy is not asserted by the public DNS monitor.
TARGETS: tuple[tuple[str, str, str], ...] = (
    ("gemini", "gemini.google.com", "proxy"),
    ("claude_web", "claude.ai", "proxy"),
    ("claude_api", "api.anthropic.com", "proxy"),
    ("grok", "grok.com", "proxy"),
    ("x_api", "api.x.ai", "proxy"),
    ("x", "x.com", "proxy"),
    ("tiktok_web", "www.tiktok.com", "proxy"),
    ("tiktok_api", "api.tiktokv.com", "proxy"),
    ("microsoft", "copilot.microsoft.com", "observe"),
)
STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([1-5][0-9]{2})(?:[ \t].*)?$")


def categorize_http(status: int | None) -> str:
    """Never equate a remote 403/429/5xx with verified app failure."""
    if status is None:
        return "unknown"
    if 200 <= status <= 399:
        return "http_response_2xx_3xx"
    if status in (401, 403, 404, 405, 407, 451):
        return "http_response_restricted_or_path_specific"
    if status == 429:
        return "http_rate_limited"
    if 500 <= status <= 599:
        return "http_response_5xx_unverified"
    return "http_other_response"


def parse_status(data: bytes) -> int | None:
    """Only the initial HTTP/1.x status line; never read or log a body."""
    if not isinstance(data, bytes):
        return None
    line = data.split(b"\r\n", 1)[0]
    if len(line) > 128:
        return None
    match = STATUS_LINE.fullmatch(line)
    return int(match.group(1)) if match else None


def probe(label: str, hostname: str, route: str, timeout: float = 4.0) -> dict:
    if (not 1 <= timeout <= 10 or
            not any((label, hostname, route) == triple for triple in TARGETS)):
        raise ValueError("unapproved target or timeout")
    started = time.monotonic()
    report = {
        "service": label,
        "expected": route,
        "tls": "unknown",
        "http": "not_checked",
        "http_status": None,
        "elapsed_ms": None,
        "error_class": None,
    }
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=timeout) as sock:
            sock.settimeout(timeout)
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            # Certificate verification is required; SNI is the ORIGINAL host.
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                if not tls.version():
                    raise ssl.SSLError("TLS version missing")
                report["tls"] = "pass"
                req = (
                    f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
                    "User-Agent: MNEBYDNS-readonly-synthetic/1.0\r\n"
                    "Accept: */*\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                tls.sendall(req)
                line = bytearray()
                while b"\r\n" not in line and len(line) < 128:
                    part = tls.recv(min(128 - len(line), 128))
                    if not part:
                        break
                    line.extend(part)
                status = parse_status(bytes(line))
                report["http_status"] = status
                report["http"] = categorize_http(status)
    except (OSError, ValueError, EOFError, ssl.SSLError) as exc:
        # Report only the exception TYPE. No remote text, URLs or credentials.
        report["error_class"] = type(exc).__name__
        if report["tls"] != "pass":
            report["tls"] = "fail"
        else:
            report["http"] = "unknown_after_verified_tls"
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
    return report


def collect(targets: tuple[tuple[str, str, str], ...] = TARGETS,
            worker_count: int = 2) -> dict:
    if not 1 <= worker_count <= 3:
        raise ValueError("worker count out of bounds")
    if not targets or len(set(targets)) != len(targets) or any(t not in TARGETS for t in targets):
        raise ValueError("unapproved targets")
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
        tasks = [pool.submit(probe, *target) for target in targets]
        services = [f.result() for f in tasks]
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "vantage": "foreign_vps_loopback_443_not_end_user",
        "client_end_to_end_verified": False,
        "per_service_egress_verified": False,
        "automatic_failover_enabled": False,
        "data_plane_mutation": False,
        "scope": "synthetic_tls_certificate_and_http_status_line_only",
        "total": len(services),
        "tls_verified": sum(s["tls"] == "pass" for s in services),
        "http_2xx_3xx": sum(s["http"] == "http_response_2xx_3xx" for s in services),
        "services": services,
    }


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, separators=(",", ":")), flush=True)
