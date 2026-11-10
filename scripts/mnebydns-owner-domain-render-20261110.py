#!/usr/bin/env python3
"""Exact-hostname owner SmartDNS route renderer.

No shell interpolation, wildcard SNI proxy, unverified origin IP or private
destination. Pinned upstream IP keeps TLS certificate and original SNI intact.
Changes only TWO owned files: CoreDNS Corefile and primary nginx.conf.
"""
from __future__ import annotations

import argparse
import ipaddress
import pathlib
import re
import socket
import ssl

EDGE = "89.125.90.101"
KINDS = ("A", "AAAA", "HTTPS", "SVCB", "CNAME")
DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
FORBIDDEN = re.compile(r"\.(?:localhost|local|internal|test|invalid|example|onion|arpa|lan|home|corp)$")
NGINX_ANCHOR = "map $ssl_preread_server_name $direct_mtproxy_backend {"
CACHE_ANCHOR = "    cache 30\n"


def validate_domain(name: str) -> str:
    if not isinstance(name, str) or len(name) > 253 or not DOMAIN.fullmatch(name):
        raise ValueError("Invalid ASCII fully qualified hostname")
    if FORBIDDEN.search(name) or "xn--" in name:
        raise ValueError("Unsafe or unreviewed hostname")
    return name


def validated_public_ip(ip: str) -> str:
    parsed = ipaddress.ip_address(ip)
    if parsed.version != 4 or not parsed.is_global:
        raise ValueError("Only globally routable IPv4 origin allowed")
    if str(parsed) in (EDGE, "188.120.254.223"):
        raise ValueError("Self-reference to SmartDNS edge")
    return str(parsed)


def origin_ip(host: str) -> str:
    validate_domain(host)
    candidates = sorted({
        validated_public_ip(result[4][0])
        for result in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
    })
    if not candidates:
        raise RuntimeError("No permitted IPv4 origin")
    ctx = ssl.create_default_context()
    for ip in candidates[:6]:
        try:
            with socket.create_connection((ip, 443), timeout=5) as tcp:
                tcp.settimeout(5)
                with ctx.wrap_socket(tcp, server_hostname=host) as tls:
                    if tls.getpeercert():
                        return ip
        except (OSError, ssl.SSLError):
            continue
    raise RuntimeError("No IPv4 origin with verified TLS certificate")


def mark(domain: str) -> str:
    return "MNEBYDNS_OWNER_EXACT_" + domain.replace(".", "_")


def _block_bounds(src: str, domain: str) -> tuple[str, str]:
    label = mark(domain)
    return "# BEGIN " + label + "\n", "# END " + label + "\n"



def _assert_no_existing_core_route(source: str, domain: str) -> None:
    """Reject overlap with CoreDNS templates, including regex in zone '.'.

    This is deliberately conservative: an unparseable existing rule must not
    be overridden on a shared production DNS server.
    """
    host = domain + "."
    header = re.compile(
        r"(?m)^[ \t]*template[ \t]+(IN|ANY)[ \t]+([A-Za-z]+)[ \t]+([^ \t\r\n{}]+)[ \t]*\{"
    )
    for item in header.finditer(source):
        _, kind, zone = item.groups()
        if kind.upper() not in (*KINDS, "ANY"):
            continue
        z = zone.rstrip(".").lower()
        if z not in ("", domain) and not domain.endswith("." + z):
            continue
        # Find matching braces, including the doubled braces in Go templates.
        depth = 1
        pos = item.end()
        while pos < len(source) and depth:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1
        if depth:
            raise ValueError("Unparseable existing CoreDNS template")
        body = source[item.end():pos-1]
        # CoreDNS template without match regex handles every name in zone.
        matches = re.findall(r"(?m)(?:^|[ \t])match[ \t]+([^\r\n}]+)", body)
        if not matches:
            raise ValueError("Existing CoreDNS zone already owns hostname")
        for raw in matches:
            pattern = raw.strip()
            if pattern.startswith('"') and pattern.endswith('"'):
                pattern = pattern[1:-1]
            elif " " in pattern or "\t" in pattern or '"' in pattern:
                raise ValueError("Unparseable CoreDNS match regex")
            try:
                if re.search(pattern, host):
                    raise ValueError("Existing CoreDNS template already covers hostname")
            except re.error as e:
                raise ValueError("Cannot prove existing CoreDNS regex does not overlap") from e
    # Imports can contain hidden templates not visible in the candidate file.
    if re.search(r"(?m)^[ \t]*import[ \t]+\S+", source):
        raise ValueError("Unexpanded CoreDNS imports forbid owner route updates")


def _assert_no_existing_nginx_route(source: str, domain: str) -> None:
    """Inspect the effective SNI map, not just literal exact-host entries."""
    if source.count(NGINX_ANCHOR) != 1:
        raise ValueError("Unrecognized stream map")
    start = source.index(NGINX_ANCHOR) + len(NGINX_ANCHOR)
    closing = re.search(r"(?m)^[ \t]*}[ \t]*(?:#.*)?$", source[start:])
    if not closing:
        raise ValueError("Cannot locate Nginx SNI map closing brace")
    section = source[start:start+closing.start()]
    hostnames = bool(re.search(r"(?m)^[ \t]*hostnames[ \t]*;", section))
    seen_default = False
    for raw in section.splitlines():
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped in ("hostnames;", "volatile;"):
            continue
        entry = re.fullmatch(r"(\S+)[ \t]+(.+);", stripped)
        if not entry:
            raise ValueError("Unknown Nginx SNI map entry")
        key = entry.group(1)
        if key == "default":
            seen_default = True
            continue
        if key == "include":
            raise ValueError("Nginx SNI map includes unknown routes")
        if key.startswith("~*") or key.startswith("~"):
            insensitive = key.startswith("~*")
            pattern = key[2:] if insensitive else key[1:]
            try:
                if re.search(pattern, domain, re.I if insensitive else 0):
                    raise ValueError("Existing regex SNI route covers hostname")
            except re.error as e:
                raise ValueError("Cannot prove Nginx regex does not overlap") from e
        elif key.casefold() == domain.casefold():
            raise ValueError("Existing exact SNI hostname route")
        elif hostnames and key.startswith("*.") and domain.endswith(key[1:].lower()):
            raise ValueError("Existing wildcard SNI route covers hostname")
        elif hostnames and key.startswith(".") and (
                domain == key[1:].lower() or domain.endswith(key.lower())):
            raise ValueError("Existing wildcard SNI route covers hostname")
        elif hostnames and key.endswith(".*") and domain.startswith(key[:-1].lower()):
            raise ValueError("Existing wildcard SNI route covers hostname")
        elif "*" in key:
            raise ValueError("Unknown Nginx wildcard SNI routing")
    if not seen_default:
        raise ValueError("SNI map default route missing")


def core_add(stable: str, domain: str) -> str:
    validate_domain(domain)
    begin, end = _block_bounds(stable, domain)
    if begin in stable or end in stable:
        raise ValueError("Already has owner domain route")
    if stable.count(CACHE_ANCHOR) != 1 or "template IN A gemini.google.com {" not in stable:
        raise ValueError("Unrecognized CoreDNS stable baseline")
    _assert_no_existing_core_route(stable, domain)
    hostname = re.escape(domain).replace(r"\.", "[.]")
    prefix = begin + "    # Owner-only exact domain, independent public TLS ingress\n"
    for kind in KINDS:
        body = '        answer "{{ .Name }} 20 IN A ' + EDGE + '"\n' if kind == "A" \
            else "        rcode NOERROR\n"
        prefix += (
            "    template IN "+kind+" . {\n"
            "        match ^"+hostname+r"[.]$"+"\n"
            + body
            + "        fallthrough\n"
            "    }\n"
        )
    prefix += end
    out = stable.replace(CACHE_ANCHOR, prefix+CACHE_ANCHOR, 1)
    if out.replace(prefix, "", 1) != stable:
        raise AssertionError("CoreDNS edit must be additive")
    return out


def nginx_add(stable: str, domain: str, ip: str) -> str:
    validate_domain(domain)
    ip = validated_public_ip(ip)
    begin, end = _block_bounds(stable, domain)
    if begin in stable or end in stable:
        raise ValueError("Already has Nginx owner domain route")
    if not re.search(r"\bproxy_pass\s+\$direct_mtproxy_backend\s*;", stable):
        raise ValueError("Expected SNI router is absent")
    _assert_no_existing_nginx_route(stable, domain)
    start = stable.index(NGINX_ANCHOR)+len(NGINX_ANCHOR)
    # PIN origin to an independently verified public IP. Never forward
    # arbitrary client SNI through DNS resolution or a wildcard open proxy.
    block = "\n        "+begin+"        "+domain+" "+ip+":443;\n        "+end
    out = stable[:start]+block+stable[start:]
    if out.replace(block, "", 1) != stable:
        raise AssertionError("Nginx edit must be additive")
    return out


def core_remove(current: str, domain: str) -> str:
    begin, end = _block_bounds(current, domain)
    a = current.find(begin)
    b = current.find(end)
    if a < 0 or b < 0 or current.count(begin) != 1 or current.count(end) != 1:
        raise ValueError("Cannot safely find exact CoreDNS owner block")
    start = current.rfind("    "+begin, 0, a+len(begin))
    if start < 0:
        start = a
    return current[:start]+current[b+len(end):]


def nginx_remove(current: str, domain: str) -> str:
    begin, end = _block_bounds(current, domain)
    a = current.find(begin)
    b = current.find(end)
    if a < 0 or b < 0 or current.count(begin) != 1 or current.count(end) != 1:
        raise ValueError("Cannot safely find exact Nginx owner block")
    start = current.rfind("\n        "+begin, 0, a+len(begin))
    if start < 0:
        raise ValueError("Nginx block prefix mismatch")
    return current[:start]+current[b+len(end):]


def self_test() -> None:
    c = ("tls://.:853 {\n"
         "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
         + CACHE_ANCHOR + "}\n")
    n = ("stream {\n"+NGINX_ANCHOR+"\n"
         "  default 127.0.0.1:9443;\n"
         "  gemini.google.com 127.0.0.1:15443;\n"
         "}\n  server { proxy_pass $direct_mtproxy_backend; }\n}\n")
    for name in ("oracle.com", "cloud.oracle.com", "www.oracle.com"):
        cp=core_add(c,name)
        np=nginx_add(n,name,"93.184.215.14")
        assert core_remove(cp,name)==c
        assert nginx_remove(np,name)==n
        assert cp.count(mark(name))==2
        assert np.count(mark(name))==2
        for invalid in ("localhost","evil.internal","http://oracle.com",
                        "*.oracle.com","xn--e1afmkfd.xn--p1ai"):
            try:validate_domain(invalid)
            except ValueError:continue
            raise AssertionError("Unsafe domain accepted")
    for ip in ("127.0.0.1","169.254.169.254","192.168.1.1",
               "10.66.77.1","188.120.254.223",EDGE,"::1"):
        try:validated_public_ip(ip)
        except ValueError:continue
        raise AssertionError("Unsafe destination accepted")
    print("owner_dns_renderer_strict_additive_roundtrip=PASS",flush=True)


def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("command",choices=("self-test","probe","render-add","render-remove"))
    p.add_argument("--domain")
    p.add_argument("--ip")
    p.add_argument("--core")
    p.add_argument("--nginx")
    p.add_argument("--out")
    args=p.parse_args()
    if args.command=="self-test":
        self_test()
        return
    if not args.domain:
        p.error("domain required")
    domain=validate_domain(args.domain)
    if args.command=="probe":
        print(origin_ip(domain),flush=True)
        return
    if not args.core or not args.nginx or not args.out:
        p.error("core, nginx and out required")
    target=pathlib.Path(args.out)
    if target.is_symlink() or not target.is_dir():
        raise ValueError("Output directory must exist and not be a symlink")
    core=pathlib.Path(args.core).read_text()
    nginx=pathlib.Path(args.nginx).read_text()
    if args.command=="render-add":
        if not args.ip:p.error("ip required for add")
        dns_new=core_add(core,domain)
        nginx_new=nginx_add(nginx,domain,args.ip)
    else:
        dns_new=core_remove(core,domain)
        nginx_new=nginx_remove(nginx,domain)
    for name,content in (("dns.pilot",dns_new),("nginx.pilot",nginx_new)):
        path=target/name
        with path.open("x") as out:
            out.write(content)
        path.chmod(0o600)
    print("owner_dns_renderer_exact_domain_ready=true",flush=True)

if __name__=="__main__":
    main()
