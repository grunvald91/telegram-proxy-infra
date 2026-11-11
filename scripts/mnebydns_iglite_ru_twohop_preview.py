#!/usr/bin/env python3
"""No-deploy proof of the required Android -> RU -> WG -> DE -> Meta path.

Given text snapshots of the *current* RU and DE nginx configurations and the
current DE DoT Corefile, prepare two isolated candidate file contents:
- public DoT A for one exact Lite hostname -> Russian IPv4;
- DE nginx exact original SNI -> independently verified public Meta IPv4.
RU nginx is NOT modified: it must already forward default TLS transparently
to the private WireGuard endpoint on DE. No DNS, firewall or service writes.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re

HOST = "iglite-z.instagram.com"
RU = "188.120.254.223"
DE = "89.125.90.101"
WG_DE = "10.66.77.1:443"

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "owner_exact_renderer", BASE / "mnebydns-owner-domain-render-20261110.py"
)
if spec is None or spec.loader is None:
    raise RuntimeError("Missing owner renderer")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def check_ru_passthrough(nginx: str) -> None:
    """Fail closed unless an unchanged RU SNI map safely defaults over WG."""
    anchor = m.NGINX_ANCHOR
    if nginx.count(anchor) != 1:
        raise ValueError("RU SNI map differs from tested main architecture")
    m._assert_no_existing_nginx_route(nginx, HOST)
    if not re.search(r"\bproxy_pass\s+\$direct_mtproxy_backend\s*;", nginx):
        raise ValueError("RU Nginx does not use tested TCP SNI passthrough")
    tail = nginx.split(anchor, 1)[1]
    close = re.search(r"(?m)^[ \t]*}[ \t]*(?:#.*)?$", tail)
    if not close:
        raise ValueError("Unclosed RU map")
    section = tail[:close.start()]
    defaults = re.findall(r"(?m)^[ \t]*default[ \t]+([^;\s]+)[ \t]*;", section)
    if defaults != [WG_DE]:
        raise ValueError("RU default is not the pinned private DE WireGuard backend")


def plan(core: str, ru_nginx: str, de_nginx: str, origin_ip: str):
    """Return (candidate Corefile, candidate DE nginx.conf) without applying."""
    if m.validate_domain(HOST) != HOST or DE != m.EDGE:
        raise AssertionError("Unexpected owner exact route policy")
    if m.validated_public_ip(origin_ip) != origin_ip:
        raise ValueError("Meta origin must be a canonical public IPv4")
    check_ru_passthrough(ru_nginx)
    new_core = m.core_add(core, HOST)
    begin, end = m._block_bounds(new_core, HOST)
    a = new_core.index(begin)
    b = new_core.index(end, a) + len(end)
    block = new_core[a:b]
    de_answer = 'answer "{{ .Name }} 20 IN A ' + DE + '"'
    ru_answer = 'answer "{{ .Name }} 20 IN A ' + RU + '"'
    if block.count(de_answer) != 1 or block.count(ru_answer) != 0:
        raise AssertionError("Owner DNS candidate is not a single exact A rewrite")
    updated = block.replace(de_answer, ru_answer, 1)
    new_core = new_core[:a] + updated + new_core[b:]
    new_de = m.nginx_add(de_nginx, HOST, origin_ip)

    if m.core_remove(new_core, HOST) != core:
        raise AssertionError("DNS rollback is not byte-identical")
    if m.nginx_remove(new_de, HOST) != de_nginx:
        raise AssertionError("DE Nginx rollback is not byte-identical")
    if ru_nginx.count(HOST):
        raise AssertionError("RU must not have a newly inserted Lite route")
    if new_core.count(ru_answer) != 1:
        raise AssertionError("Missing exact RU A answer")
    if '        ' + HOST + ' ' + origin_ip + ':443;' not in new_de:
        raise AssertionError("DE origin SNI route missing")
    if '        ' + HOST + ' ' + RU + ':443;' in new_de:
        raise AssertionError("Accidental RU-to-RU routing loop")
    return new_core, new_de
