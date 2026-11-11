#!/usr/bin/env python3
"""Offline-verifiable CoreDNS/Nginx route predicates for Wi-Fi readiness.

CoreDNS exact host matches are Go regexes such as
  match ^iglite\-z[.]instagram[.]com[.]$
and NOT plain dotted hostnames. Do not use 'hostname in corefile' as a gate.
"""
from __future__ import annotations
import re

def core_exact_host_ready(corefile: str, hostname: str) -> bool:
    escaped = re.escape(hostname).replace(r'\.', '[.]')
    pattern = 'match ^' + escaped + '[.]$'
    # Five A/AAAA/HTTPS/SVCB/CNAME templates are installed per exact route.
    return corefile.count(pattern) == 5

def nginx_exact_host_ready(nginx: str, hostname: str) -> bool:
    # Match only full stream route lines, not incidental mention in comments.
    pattern = (r'(?m)^\s*' + re.escape(hostname) +
               r'\s+(?:\d{1,3}\.){3}\d{1,3}:443;\s*$')
    return re.search(pattern, nginx) is not None

def all_hosts_ready(corefile: str, nginx: str, hostnames) -> bool:
    hosts = tuple(hostnames)
    return bool(hosts) and len(hosts) == len(set(hosts)) and all(
        core_exact_host_ready(corefile, h) and nginx_exact_host_ready(nginx, h)
        for h in hosts)
