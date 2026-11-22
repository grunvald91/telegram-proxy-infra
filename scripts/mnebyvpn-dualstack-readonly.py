#!/usr/bin/env python3
"""MNEBYVPN dual-stack inventory. READ-ONLY, no tokens/peer addresses or configs printed.

Usage:
  python3 scripts/mnebyvpn-dualstack-readonly.py --host RU188|DE89|FI217
  python3 scripts/mnebyvpn-dualstack-readonly.py --public
No privileges are required for the Python code itself.
"""
import ipaddress
import json
import re
import socket
import subprocess
import sys


PORTS = (443, 853, 9446, 51820, 51821)


def cmd(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=6, check=False)
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def jsoncmd(*args):
    data = cmd(*args)
    if data is None:
        return None
    try:
        return json.loads(data)
    except (ValueError, TypeError):
        return None


def sysctl(key):
    text = cmd("sysctl", "-n", key)
    if text is None:
        return None
    val = text.strip()
    return val if val in ("0", "1") else None


def listener_ports(ip_version, transport):
    if transport not in ("tcp", "udp") or ip_version not in (4, 6):
        return None
    # -l: listening, -n: numeric, -H: no header; address family is explicit.
    data = cmd("ss", f"-{ip_version}", "-H", "-lnt" if transport == "tcp" else "-lnu")
    if data is None:
        return None
    found = set()
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        address = fields[4] if fields[0].lower() in ("tcp", "udp") and len(fields) > 5 else fields[3]
        match = re.search(r":(\d{1,5})$", address)
        if match:
            found.add(int(match.group(1)))
    return {str(p): p in found for p in PORTS}


def has_global_ipv6():
    data = jsoncmd("ip", "-j", "-6", "addr", "show")
    if data is None:
        return None
    for dev in data:
        for addr in dev.get("addr_info", []):
            candidate = addr.get("local")
            if not candidate or addr.get("scope") != "global":
                continue
            try:
                if ipaddress.IPv6Address(candidate).is_global:
                    return True
            except ValueError:
                pass
    return False


def default_route(family):
    routes = jsoncmd("ip", "-j", f"-{family}", "route", "show", "default")
    if routes is None:
        return None
    return any(r.get("dst", "default") == "default" and r.get("type") not in ("blackhole", "unreachable") for r in routes)


def tcp_probe(family, address, port, timeout=3):
    try:
        with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((address, port))
        return True
    except OSError:
        return False


def addresses(host, family):
    try:
        result = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        return sorted({x[4][0] for x in result})
    except OSError:
        return []


def public():
    report = {"scope": "public", "read_only": True, "note": "DNS records and TCP only; not authenticated E2E"}
    for tag, host in (
        ("website", "mnebyvpn.site"),
        ("fi", "fi.mnebyvpn.site"),
        ("personal_dns_wildcard_test", "aaaaaaaaaaaa.dns.mnebyvpn.site"),
    ):
        v4 = addresses(host, socket.AF_INET)
        v6 = addresses(host, socket.AF_INET6)
        report[tag + "_a_present"] = bool(v4)
        report[tag + "_aaaa_present"] = bool(v6)
        # A and AAAA alone are NOT proof that the backed service is IPv6-ready.
        if tag == "personal_dns_wildcard_test":
            report["personal_dns_tcp853_ipv4"] = bool(v4) and any(tcp_probe(4, ip, 853) for ip in v4[:2])
            report["personal_dns_tcp853_ipv6"] = bool(v6) and any(tcp_probe(6, ip, 853) for ip in v6[:2])
    report["ru188_tcp853_ipv4"] = tcp_probe(4, "188.120.254.223", 853)
    report["de89_tcp9446_ipv4"] = tcp_probe(4, "89.125.90.101", 9446)
    report["runner_ipv6_egress"] = tcp_probe(6, "2606:4700:4700::1111", 443)
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))


def host(label):
    if label not in ("RU188", "DE89", "FI217"):
        raise SystemExit("unknown node")
    report = {
        "scope": label,
        "read_only": True,
        "ipv6_disabled_global": sysctl("net.ipv6.conf.all.disable_ipv6"),
        "ipv6_forwarding": sysctl("net.ipv6.conf.all.forwarding"),
        "ipv4_forwarding": sysctl("net.ipv4.ip_forward"),
        "global_ipv6_address_present": has_global_ipv6(),
        "default_ipv4_route": default_route(4),
        "default_ipv6_route": default_route(6),
        "ipv6_egress_tcp443": tcp_probe(6, "2606:4700:4700::1111", 443),
        "tcp_ipv4_listeners": listener_ports(4, "tcp"),
        "tcp_ipv6_listeners": listener_ports(6, "tcp"),
        "udp_ipv4_listeners": listener_ports(4, "udp"),
        "udp_ipv6_listeners": listener_ports(6, "udp"),
        "note": "A listening socket does not prove external reachability or IPv6 full-tunnel capability",
    }
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))


def main():
    if sys.argv[1:] == ["--public"]:
        public()
    elif len(sys.argv) == 3 and sys.argv[1] == "--host":
        host(sys.argv[2])
    else:
        raise SystemExit("usage: --public | --host RU188|DE89|FI217")


if __name__ == "__main__":
    main()
