#!/usr/bin/env python3
"""Strict additive shared Threads API host only, for the existing time-bounded pilot.

This does not enable the Instagram application or alter Instagram's other hosts.
Existing pilot backup files must be reconciled by the guarded stage; never use
this to mutate a production Corefile without the pilot's existing watchdog.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import re

HOST="i.instagram.com"
A_IP="188.120.254.223"
MARK="MNEBYDNS_THREADS_SHARED_API_I_20261110"
DNS_ANCHOR="    cache 30\n"
MAP="map $ssl_preread_server_name $direct_mtproxy_backend {"

def render_dns(src: str) -> str:
    if MARK in src or src.count(DNS_ANCHOR)!=1:
        raise ValueError("DNS not an exact known pilot")
    if src.count("MNEBYDNS_THREADS_ONLY_20261110")!=1:
        raise ValueError("Threads-only DNS pilot not present")
    if re.search(r"template\s+IN\s+(?:A|AAAA|HTTPS|SVCB|CNAME)\s+(?:i[.]instagram[.]com|[.])\s*\{[^{}]*i[.]instagram[.]com",src,re.I):
        raise ValueError("Shared API host already has an owner")
    addition="\n    # "+MARK+" temporary per-host addition, expires with Threads pilot\n"
    for record in ("A","AAAA","HTTPS","SVCB","CNAME"):
        payload=('        answer "{{ .Name }} 20 IN A '+A_IP+'"\n'
                 if record=="A" else "        rcode NOERROR\n")
        addition+=("    template IN "+record+" . {\n"
                   "        match (?i)^i[.]instagram[.]com[.]$\n"
                   +payload+"        fallthrough\n"
                   "    }\n")
    out=src.replace(DNS_ANCHOR,addition+DNS_ANCHOR,1)
    if out.replace(addition,"",1)!=src:
        raise AssertionError("DNS outside-addition mutation")
    return out

def render_nginx(src: str) -> str:
    if MARK in src or src.count(MAP)!=1:
        raise ValueError("Nginx map not a known Threads pilot")
    if src.count("MNEBYDNS_THREADS_ONLY_20261110")!=1:
        raise ValueError("Threads-only Nginx pilot missing")
    if re.search(r"(?m)^\s*i[.]instagram[.]com\s+",src):
        raise ValueError("Shared API SNI route pre-owned")
    insertion="\n        # "+MARK+"\n        "+HOST+" $ssl_preread_server_name:443;\n"
    out=src.replace(MAP,MAP+insertion,1)
    if out.replace(insertion,"",1)!=src:
        raise AssertionError("Nginx outside-addition mutation")
    return out

def self_test():
    dns=("tls://.:853 {\n"
         "    # MNEBYDNS_THREADS_ONLY_20261110\n"
         "    template IN A . {\n"
         "        match (?i)^www[.]threads[.]com[.]$\n"
         '        answer "{{ .Name }} 20 IN A 188.120.254.223"\n'
         "    }\n    cache 30\n}\n")
    nginx=("stream {\n"+MAP+"\n"
           "    # MNEBYDNS_THREADS_ONLY_20261110\n"
           "    default 127.0.0.1:443;\n}\n}\n")
    d=render_dns(dns);n=render_nginx(nginx)
    assert d.count(MARK)==1 and n.count(MARK)==1
    assert d.count("template IN ")==6
    assert d.count("match (?i)^i[.]instagram[.]com[.]$")==5
    assert d.count('IN A '+A_IP)==2
    assert n.count(HOST+" $ssl_preread_server_name:443;")==1
    assert "www[.]threads[.]com" in d
    assert "default 127.0.0.1:443;" in n
    assert "facebook.com" not in d+n
    try:render_dns(d)
    except ValueError:pass
    else:raise AssertionError("Double-patch allowed")
    print("threads_shared_api_one_exact_host_additive=PASS",flush=True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=("self-test","render"))
    parser.add_argument("--dns")
    parser.add_argument("--nginx")
    parser.add_argument("--out")
    args=parser.parse_args()
    if args.action=="self-test":
        self_test();return
    if not args.dns or not args.nginx or not args.out:
        parser.error("render needs dns, nginx and out")
    out=Path(args.out)
    if not out.is_dir() or out.is_symlink():raise ValueError("Invalid output dir")
    for name,body in (("dns.api",render_dns(Path(args.dns).read_text())),
                      ("nginx.api",render_nginx(Path(args.nginx).read_text()))):
        (out/name).write_text(body)
    print("threads_shared_api_rendered=true",flush=True)

if __name__=="__main__":main()
