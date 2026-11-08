#!/usr/bin/env python3
"""Strict exact-host MNEBYDNS Google canary config renderer.

The active shared Nginx stream map and CoreDNS file are INPUTS, not mutated
by this program. Unknown revisions, wildcard rules, duplicate hosts and
missing legacy routes fail closed. No subscriber identifiers or secrets.
"""
from __future__ import annotations
import argparse
import pathlib
import re

INGRESS="89.125.90.101"
BACKEND="127.0.0.1:15449"
TARGETS=(
    ("gemini","jnn-pa.googleapis.com"),
    ("gemini","waa-pa.clients6.google.com"),
    ("youtube","www.youtube.com"),
    ("youtube","youtubei.googleapis.com"),
    ("youtube","i.ytimg.com"),
    ("youtube","s.ytimg.com"),
    ("stitch","stitch.withgoogle.com"),
    ("aistudio","aistudio.google.com"),
    ("aistudio","generativelanguage.googleapis.com"),
)
HOSTS=tuple(host for service,host in TARGETS)
MAP=re.compile(
    r"(map\s+\$ssl_preread_server_name\s+\$direct_mtproxy_backend\s*\{)"
    r"([^{}]*)(\})",re.S
)
EXISTING=("gemini.google.com","cdn.servgo.ru","tg.servgo.ru")
CACHE="    cache 30\n"
ROUTE_TAG="# MNEBYDNS exact-four-google pilot 2026-11-08"

def render_nginx(source:str)->str:
    maps=list(MAP.finditer(source))
    if len(maps)!=1:
        raise ValueError("Shared Nginx SNI map unexpectedly absent or ambiguous")
    match=maps[0]
    body=match.group(2)
    lines=body.splitlines()
    if not any(re.match(r"^\s*default\s+[^;]+;",x) for x in lines):
        raise ValueError("Missing shared SNI default")
    for host in EXISTING:
        if sum(bool(re.match(r"^\s*"+re.escape(host)+r"\s+\S+;",x)) for x in lines)!=1:
            raise ValueError("Existing route missing or ambiguous: "+host)
    if not re.search(r"(?m)^\s*gemini[.]google[.]com\s+127[.]0[.]0[.]1:15443;",body):
        raise ValueError("Verified Gemini root backend missing")
    for host in HOSTS:
        if re.search(r"(?m)^\s*"+re.escape(host)+r"\s+\S+;",body):
            raise ValueError("Target already has live SNI route: "+host)
    if ROUTE_TAG in source or BACKEND in source:
        raise ValueError("Existing pilot or backend port conflict")
    # Existing regex/wildcards stay untouched; explicit Nginx map names
    # take precedence. Strict exact FQDN only; nothing open-proxy.
    insert="\n        "+ROUTE_TAG+"\n"
    insert+="".join("        "+host+" "+BACKEND+";\n" for host in HOSTS)
    out=source[:match.start(2)]+insert+source[match.start(2):]
    if out.replace(insert,"",1)!=source:
        raise AssertionError("Not a strictly additive Nginx modification")
    return out

def template(host:str,kind:str)->str:
    exact="^"+re.escape(host).replace(r"\.","[.]")+"[.]$"
    ans=(f'        answer "{{{{ .Name }}}} 20 IN A {INGRESS}"\n'
         if kind=="A" else "        rcode NOERROR\n")
    return (f"    template IN {kind} {host} {{\n"
            f"        match {exact}\n"+ans+
            "        fallthrough\n"
            "    }\n")

def render_dns(source:str)->str:
    if source.count("template IN A gemini.google.com {")!=1:
        raise ValueError("Existing DNS Gemini root route missing or ambiguous")
    if source.count(CACHE)!=1:
        raise ValueError("Unexpected CoreDNS cache placement")
    for host in HOSTS:
        if re.search(r"(?m)^\s*template IN\s+\w+\s+"+re.escape(host)+r"\s*\{",source):
            raise ValueError("Target already has DNS policy: "+host)
    if ROUTE_TAG in source:
        raise ValueError("Canary already applied")
    insert="\n    "+ROUTE_TAG+"\n"
    for host in HOSTS:
        for kind in ("A","AAAA","HTTPS","SVCB"):
            insert+=template(host,kind)
    out=source.replace(CACHE,insert+CACHE,1)
    if out.replace(insert,"",1)!=source:
        raise AssertionError("Not a strictly additive DNS modification")
    return out

def backend_nginx()->str:
    allowed="\n".join("        "+host+" "+host+":443;" for host in HOSTS)
    return (
        "# Isolated local-only Google exact-host TLS passthrough (no TLS termination)\n"
        "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
        "worker_processes 1;\n"
        "pid /run/mnebydns-four-google/nginx.pid;\n"
        "error_log stderr warn;\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        "    resolver 9.9.9.9 ipv6=off valid=30s;\n"
        "    resolver_timeout 5s;\n"
        "    map $ssl_preread_server_name $four_google_origin {\n"
        "        default 127.0.0.1:1;\n"
        +allowed+"\n"
        "    }\n"
        "    server {\n"
        "        listen "+BACKEND+";\n"
        "        ssl_preread on;\n"
        "        proxy_pass $four_google_origin;\n"
        "        proxy_connect_timeout 7s;\n"
        "        proxy_timeout 90s;\n"
        "        proxy_buffer_size 16k;\n"
        "        access_log off;\n"
        "    }\n"
        "}\n"
    )

def main()->None:
    cli=argparse.ArgumentParser()
    cli.add_argument("nginx_input")
    cli.add_argument("dns_input")
    cli.add_argument("nginx_output")
    cli.add_argument("dns_output")
    cli.add_argument("backend_output")
    a=cli.parse_args()
    srcn=pathlib.Path(a.nginx_input)
    srcd=pathlib.Path(a.dns_input)
    outs=[pathlib.Path(x) for x in (a.nginx_output,a.dns_output,a.backend_output)]
    if not srcn.is_file() or srcn.is_symlink() or not srcd.is_file() or srcd.is_symlink():
        raise SystemExit("Missing or linked config inputs")
    if len(set(outs))!=3 or any(x.exists() or x.is_symlink() for x in outs):
        raise SystemExit("Refuse to overwrite staged config")
    outputs=(render_nginx(srcn.read_text()),
             render_dns(srcd.read_text()),backend_nginx())
    for dest,data in zip(outs,outputs):
        dest.write_text(data)
        dest.chmod(0o600)
    print("canary_exact_hosts="+str(len(HOSTS)))
    print("google_domain_wildcard_added=false")
    print("legacy_stream_routes_preserved=true")
    print("original_Gemini_and_other_DNS_preserved=true")
    print("staged_config_only_no_live_changes=true")

if __name__=="__main__":
    main()
