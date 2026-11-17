#!/usr/bin/env python3
"""Stage closed-by-default personal DoT + SNI proxy on a new Nodekit VPS.

No listeners, open resolver, open proxy, certificate issuance, firewall or
routing changes are performed. A *separately authorized* controller must
approve service activation and client-specific DNS policy in a later step.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from install_components import node_ready, safe_manifest
from nodekit import _promote_stage_noreplace
import tempfile

ROOT = Path("/var/lib/mnebyvpn-nodekit")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{1,251})[a-z0-9]\Z")


class PolicyError(ValueError):
    pass


def public_hostname(value: str) -> str:
    if (not isinstance(value, str) or len(value) > 253 or
            not HOST.fullmatch(value) or ".." in value or "." not in value or
            any(not part or len(part) > 63 or part.startswith("-")
                or part.endswith("-") for part in value.split("."))):
        raise PolicyError("Invalid DNS or SNI hostname")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise PolicyError("Hostname cannot be an IP")


def global_ipv4(value: str) -> str:
    if not isinstance(value, str):
        raise PolicyError("Invalid IPv4")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise PolicyError("Invalid IPv4") from exc
    if not address.is_global:
        raise PolicyError("Private, reserved and loopback IPs prohibited")
    return str(address)


def validate_policy(raw: dict, node_id: str) -> dict:
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version", "node_id", "external_ipv4", "dns_host", "routes"
    }:
        raise PolicyError("Unexpected DNS/proxy policy fields")
    if raw["schema_version"] != 1 or raw["node_id"] != node_id:
        raise PolicyError("DNS/proxy policy for the wrong node")
    dns_host = public_hostname(raw["dns_host"])
    ip = global_ipv4(raw["external_ipv4"])
    routes = raw["routes"]
    if not isinstance(routes, list) or len(routes) > 200:
        raise PolicyError("Too many proxy routes")
    unique = set()
    fixed = []
    for item in routes:
        if not isinstance(item, dict) or set(item) != {"domain", "upstream_ipv4"}:
            raise PolicyError("Invalid route fields")
        domain = public_hostname(item["domain"])
        upstream = global_ipv4(item["upstream_ipv4"])
        if domain in unique or domain == dns_host or upstream == ip:
            raise PolicyError("Duplicate, self-referential or unsafe route")
        unique.add(domain)
        fixed.append({"domain": domain, "upstream_ipv4": upstream})
    return {"schema_version": 1, "node_id": node_id,
            "external_ipv4": ip, "dns_host": dns_host,
            "routes": sorted(fixed, key=lambda row: row["domain"])}


def make_corefile(policy: dict, node_dir: Path) -> str:
    crt = node_dir / "tls" / "fullchain.pem"
    key = node_dir / "tls" / "privkey.pem"
    lines = [
        "# MNEBYVPN isolated CoreDNS; TLS only on loopback, never public bind.",
        "tls://127.0.0.1:8853 {",
        "  bind 127.0.0.1",
        f"  tls {crt} {key}",
        "  errors",
        "  cache 20",
    ]
    for item in policy["routes"]:
        pattern = "^" + re.escape(item["domain"]) + r"\.$"
        # Return the proxy address for approved exact QNAMEs only.
        lines += [
            "  template IN A . {",
            f"    match {pattern}",
            f'    answer "{{{{ .Name }}}} 30 IN A {policy["external_ipv4"]}"',
            "    fallthrough",
            "  }",
            "  template IN AAAA . {",
            f"    match {pattern}",
            "    rcode NOERROR",
            "    fallthrough",
            "  }",
        ]
    lines += [
        "  forward . tls://1.1.1.1 tls://1.0.0.1 {",
        "    tls_servername cloudflare-dns.com",
        "    health_check 5s",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def make_nginx_conf(policy: dict) -> str:
    lines = [
        "# Isolated nginx config. Never include this in running /etc/nginx before promotion.",
        "load_module /usr/lib/nginx/modules/ngx_stream_module.so;",
        "worker_processes 1;",
        "error_log stderr warn;",
        "pid /tmp/mnebyvpn-nodekit-nginx-test.pid;",
        "events { worker_connections 512; }",
        "stream {",
        "  map $ssl_preread_server_name $mnebyvpn_route {",
        "    default 127.0.0.1:9;",  # deny, not a catch-all CONNECT proxy
    ]
    for item in policy["routes"]:
        lines.append(f'    {item["domain"]} {item["upstream_ipv4"]}:443;')
    lines += [
        "  }",
        "  map $ssl_preread_server_name $mnebyvpn_dns_route {",
        "    default 127.0.0.1:9;",
        f'    {policy["dns_host"]} 127.0.0.1:8853;',
        "  }",
        "  server {",
        "    listen 0.0.0.0:443;",
        "    proxy_connect_timeout 5s;",
        "    proxy_timeout 120s;",
        "    proxy_pass $mnebyvpn_route;",
        "    ssl_preread on;",
        "  }",
        "  server {",
        "    listen 0.0.0.0:853;",
        "    proxy_connect_timeout 3s;",
        "    proxy_timeout 30s;",
        "    proxy_pass $mnebyvpn_dns_route;",
        "    ssl_preread on;",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def stage_dns_proxy(node: Path, policy: dict) -> dict:
    manifest = safe_manifest(node / "manifest.json")
    if (manifest.get("node_id") != node.name or
            manifest.get("advertise_host") != policy["dns_host"] or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False or
            manifest.get("listeners", {}).get("dot_tcp") != 853 or
            manifest.get("listeners", {}).get("sni_tcp") != 443):
        raise PolicyError("DNS/proxy does not match inactive node listener spec")
    stage = node / "dns-proxy"
    report = {
        "schema_version": 1, "node_id": node.name, "state": "staged",
        "route_count": len(policy["routes"]),
        "activation_enabled": False, "personal_dns_enabled": False,
        "open_proxy_enabled": False, "open_resolver_enabled": False,
        "external_e2e_verified": False,
        "pending": ["signed_policy_bundle", "certificate_valid_for_dns_host",
                    "DNS_resolver_auth", "nginx_test", "coreDNS_tls_test",
                    "external_TLS_and_DNS_e2e", "controller_release"],
    }
    core = make_corefile(policy, node)
    nginx = make_nginx_conf(policy)
    report["config_sha256"] = {
        "Corefile": hashlib.sha256(core.encode()).hexdigest(),
        "nginx.conf": hashlib.sha256(nginx.encode()).hexdigest(),
    }
    if stage.exists() or stage.is_symlink():
        if stage.is_symlink() or not stage.is_dir() or stage.stat().st_mode & 0o077:
            raise PolicyError("Unsafe existing DNS/proxy stage")
        old = safe_manifest(stage / "manifest.json")
        if old != report:
            raise PolicyError("Existing DNS/proxy manifest drift")
        for name, expected in (("Corefile", core), ("nginx.conf", nginx)):
            path = stage / name
            if path.is_symlink() or not path.is_file() or path.read_text() != expected:
                raise PolicyError("Existing DNS/proxy file drift")
        return dict(report, already_staged=True)
    work = Path(tempfile.mkdtemp(prefix=".dns-proxy-", dir=node))
    try:
        work.chmod(0o700)
        for name, content in (("Corefile", core), ("nginx.conf", nginx),
                              ("manifest.json", json.dumps(report, sort_keys=True) + "\n")):
            path = work / name
            path.write_text(content)
            path.chmod(0o600)
        # Nginx validates its candidate without touching /etc or starting services.
        subprocess.run(["nginx", "-t", "-c", str(work / "nginx.conf")],
                       check=True, timeout=12, capture_output=True)
        _promote_stage_noreplace(work, stage)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id", required=True)
    p.add_argument("--external-ipv4", required=True)
    p.add_argument("--dns-host", required=True)
    p.add_argument("--policy", type=Path)
    p.add_argument("--stage-root", type=Path, default=ROOT)
    args = p.parse_args()
    try:
        if __import__("os").geteuid() != 0:
            raise PolicyError("Root required")
        node = node_ready(args.stage_root, args.node_id)
        routes = []
        if args.policy:
            # Only operator-installed 0600 Nodekit-owned policy; signed promotion is separate.
            path = args.policy
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or (
                path.stat().st_mode & 0o077) or path.stat().st_size > 50000:
                raise PolicyError("Unsafe route policy file")
            raw = json.loads(path.read_text())
            if not isinstance(raw, list):
                raise PolicyError("Routes must be a JSON list")
            routes = raw
        policy = validate_policy({
            "schema_version": 1, "node_id": args.node_id,
            "external_ipv4": args.external_ipv4,
            "dns_host": args.dns_host, "routes": routes,
        }, args.node_id)
        print(json.dumps(stage_dns_proxy(node, policy), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("nodekit_dns_proxy_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
