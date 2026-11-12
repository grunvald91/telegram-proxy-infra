#!/usr/bin/env python3
"""Strict additive, temporary Threads-only CoreDNS + Nginx stream renderer.
Never rewrites any Instagram, Facebook, Telegram, existing service or default rule.
"""
import argparse
import pathlib
import re
import sys

DE="89.125.90.101"
TYPES=("A","AAAA","HTTPS","SVCB","CNAME")
ZONES=("threads.com","threads.net")
MATCH=r"(?i)^(?:[a-z0-9-]+[.])*(?:threads[.]com|threads[.]net)[.]$"
STREAM_MATCH=r"~*^(?:[a-z0-9-]+\.)*threads\.(?:com|net)$"

def render_corefile(stable):
    marker="    cache 30\n"
    if stable.count(marker)!=1 or stable.count("template IN A gemini.google.com {")!=1:
        raise ValueError("Unexpected CoreDNS baseline: refusing Threads patch")
    if "MNEBYDNS_THREADS_ONLY_20261110" in stable:
        raise ValueError("Already has Threads pilot")
    for name in ("threads.com","threads.net","graph.threads.com","graph.threads.net"):
        if re.search(r"template IN (?:A|AAAA|HTTPS|SVCB|CNAME)\s+"+
                     re.escape(name)+r"\s*\{",stable):
            raise ValueError("Existing Threads record owner")
    for kind in TYPES:
        if re.search(r"template IN "+kind+r" \.\s*\{\s*match "+
                     re.escape(MATCH),stable):
            raise ValueError("Existing exact Threads catchall")
    addition="\n    # MNEBYDNS_THREADS_ONLY_20261110: bounded canary; never Instagram\n"
    for kind in TYPES:
        body=(f'        answer "{{{{ .Name }}}} 20 IN A {DE}"\n'
              if kind=="A" else '        rcode NOERROR\n')
        addition+=("    template IN "+kind+" . {\n"
                   "        match "+MATCH+"\n"+body+
                   "        fallthrough\n"
                   "    }\n")
    patched=stable.replace(marker,addition+marker,1)
    if patched.replace(addition,"",1)!=stable:
        raise AssertionError("CoreDNS patch not strictly additive")
    if any(token in addition for token in ("instagram.com","facebook.com","telegram.org")):
        raise AssertionError("Forbidden domain route")
    return patched

def render_nginx(stable):
    anchor="map $ssl_preread_server_name $direct_mtproxy_backend {"
    if stable.count(anchor)!=1:
        raise ValueError("Unexpected Nginx stream map")
    if "MNEBYDNS_THREADS_ONLY_20261110" in stable:
        raise ValueError("Already has Threads pilot")
    # Keep exact, existing Threads rules or legacy regex owners untouched.
    begin=stable.index(anchor)+len(anchor)
    end=stable.find("}",begin)
    if end<0:
        raise ValueError("Missing map end")
    section=stable[begin:end]
    if re.search(r"(?m)^\s*(?:threads[.](?:com|net)|~\*.*threads).*?\s+\S+;",section,re.I):
        raise ValueError("Pre-existing Threads map owner")
    if not re.search(r"(?m)^\s*default\s+\S+;",section):
        raise ValueError("Missing default route")
    addition=("\n        # MNEBYDNS_THREADS_ONLY_20261110\n"
              "        "+STREAM_MATCH+" $ssl_preread_server_name:443;\n")
    patched=stable[:begin]+addition+stable[begin:]
    if patched.replace(addition,"",1)!=stable:
        raise AssertionError("Nginx map patch not strictly additive")
    return patched

def self_test():
    core=("tls://.:853 {\n"
          "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
          "    cache 30\n"
          "}\n")
    nginx=("stream {\n"
           "map $ssl_preread_server_name $direct_mtproxy_backend {\n"
           "  default 127.0.0.1:9443;\n"
           "  gemini.google.com 127.0.0.1:15443;\n"
           "}\n"
           "}\n")
    c=render_corefile(core)
    n=render_nginx(nginx)
    assert c.count("MNEBYDNS_THREADS_ONLY_20261110")==1
    assert n.count("MNEBYDNS_THREADS_ONLY_20261110")==1
    assert c.count("answer ")==1   # one experimental Threads A response
    assert c.count("template IN ")==len(TYPES)+1
    assert "gemini.google.com 127.0.0.1:15443;" in n
    assert re.fullmatch(MATCH,"graph.threads.com.")
    assert re.fullmatch(MATCH,"www.threads.net.")
    assert not re.fullmatch(MATCH,"www.instagram.com.")
    assert not re.fullmatch(MATCH,"notthreads.com.")
    assert not re.fullmatch(STREAM_MATCH[2:],"anything.facebook.com",re.I)
    print("threads_renderer_exact_scope_selftest=PASS",flush=True)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("command",choices=("self-test","render"))
    p.add_argument("--base-dns")
    p.add_argument("--base-nginx")
    p.add_argument("--out")
    x=p.parse_args()
    if x.command=="self-test":
        self_test();return
    if not x.base_dns or not x.base_nginx or not x.out:
        p.error("render needs --base-dns --base-nginx --out")
    dns=pathlib.Path(x.base_dns).read_text()
    nginx=pathlib.Path(x.base_nginx).read_text()
    dest=pathlib.Path(x.out)
    if not dest.is_dir() or dest.is_symlink():
        raise ValueError("Invalid output directory")
    for name,content in (("dns.pilot",render_corefile(dns)),
                         ("nginx.pilot",render_nginx(nginx))):
        path=dest/name
        with path.open("x",encoding="utf-8") as f:
            f.write(content)
        path.chmod(0o600)
    print("threads_renderer_two_exact_additions_ready=true",flush=True)

if __name__=="__main__":
    main()
