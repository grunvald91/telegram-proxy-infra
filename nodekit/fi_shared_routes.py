#!/usr/bin/env python3
"""Derive FI route candidate from the live shared DE CoreDNS A templates.

No independently maintained hostname catalog; no public listeners or
production DE/RU modifications. All five address/hint record types derive
from the same exact/family policy. The temporary SNI canary is loopback-only.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

DE="89.125.90.101"
FI="217.11.167.91"
MAX_ROUTES=8192
HOST=re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
A_BLOCK=re.compile(r"(?ms)^([ \t]*)template[ \t]+IN[ \t]+A[ \t]+(\S+)[ \t]+\{(.*?)^\1\}")
FAMILY_START="(?i)^(?:[a-z0-9-]+[.])*(?:"
FAMILY_END=")[.]$"

def need(ok,label):
    if not ok:raise ValueError(label)

def hostname(name):
    need(isinstance(name,str) and len(name)<=253 and HOST.fullmatch(name),"invalid_route_name")
    need(name.rsplit(".",1)[1] not in {"localhost","local","internal","test","invalid","example","onion","arpa","lan","home","corp"},"unsafe_route_name")
    need(name!="mnebyvpn.site" and not name.endswith(".mnebyvpn.site"),"own_service_route")
    try:ipaddress.ip_address(name)
    except ValueError:return name
    raise ValueError("route_is_ip")

def literal(pattern):
    s=pattern.removeprefix("(?i)")
    need(s.startswith("^") and s.endswith("$"),"unanchored_route")
    s=s[1:-1].replace(r"\.","[.]").replace(r"\-","-")
    need(s.endswith("[.]"),"missing_dns_root")
    # No remaining regex operators, not even an unescaped dot.
    labels=s[:-3].split("[.]")
    need(all(re.fullmatch(r"[a-z0-9-]+",x) for x in labels),"nonliteral_route")
    return hostname(".".join(labels))

def family(pattern):
    need(pattern.startswith(FAMILY_START) and pattern.endswith(FAMILY_END),"unknown_family_regex")
    roots=[]
    for item in pattern[len(FAMILY_START):-len(FAMILY_END)].split("|"):
        roots.append(literal("^"+item+"[.]$"))
    need(roots and len(roots)==len(set(roots)),"duplicate_family_root")
    return roots

def parse(core):
    need(isinstance(core,str) and len(core)<=2_000_000,"source_size")
    need(not re.search(r"(?m)^\s*import\s+",core),"unexpanded_source_import")
    blocks=list(A_BLOCK.finditer(core))
    total=len(re.findall(r"(?m)^[ \t]*template[ \t]+IN[ \t]+A[ \t]+\S+[ \t]+\{",core))
    need(len(blocks)==total and total>=264,"source_a_template_coverage")
    exact=set();roots=set()
    for m in blocks:
        zone=m[2].rstrip(".") if m[2]!="." else "."
        matches=re.findall(r"(?m)^[ \t]*match[ \t]+(.+?)\s*$",m[3])
        answers=re.findall(r'(?m)^[ \t]*answer[ \t]+"{{ \.Name }} [0-9]+ IN A ([0-9.]+)"[ \t]*$',m[3])
        need(len(matches)==1 and answers==[DE],"unexpected_shared_A_template")
        # Fail on extra answer/rcode instead of silently omitting behavior.
        need(len(re.findall(r"(?m)^[ \t]*answer[ \t]+",m[3]))==1 and not re.search(r"(?m)^[ \t]*rcode[ \t]+",m[3]),"unsupported_shared_A_behavior")
        pattern=matches[0]
        if pattern.startswith(FAMILY_START):
            need(zone==".","family_zone_mismatch")
            roots.update(family(pattern))
        else:
            name=literal(pattern)
            need(zone=="." or hostname(zone)==name,"exact_zone_mismatch")
            exact.add(name)
    need(len(exact)>=262 and len(roots)>=75 and len(exact|roots)<=MAX_ROUTES,"source_catalog_bounds")
    return {"exact":sorted(exact),"families":sorted(roots)}

def covered(policy,name):
    return name in policy["exact"] or any(name==r or name.endswith("."+r) for r in policy["families"])

def render_core(policy,base):
    marker="  forward . tls://1.1.1.1 tls://1.0.0.1 {"
    need(base.count(marker)==1 and "tls://.:8853 {" in base and "  bind 127.0.0.1" in base,"private_base_drift")
    need("template IN " not in base,"private_base_already_routed")
    # Combine exact and family patterns to avoid thousands of repeated blocks.
    def esc(name):return name.replace(".","[.]")
    exact="(?i)^(?:"+ "|".join(map(esc,policy["exact"])) +")[.]$"
    family_pattern=FAMILY_START+"|".join(map(esc,policy["families"]))+FAMILY_END
    rows=[]
    for pattern in (exact,family_pattern):
        for kind in ("A","AAAA","CNAME","HTTPS","SVCB"):
            rows.extend(["  template IN "+kind+" . {","    match "+pattern,
                '    answer "{{ .Name }} 30 IN A '+FI+'"' if kind=="A" else "    rcode NOERROR",
                "    fallthrough","  }"])
    return base.replace("tls://.:8853 {","tls://.:18855 {").replace(marker,"\n".join(rows)+"\n"+marker)

def render_nginx(policy):
    # Only loopback canary. Real public rollout must add independent
    # destination-IP enforcement, and must not expose this configuration.
    roots=set(policy["families"])
    exact=[x for x in policy["exact"] if not any(x==r or x.endswith("."+r) for r in roots)]
    rows=["load_module /usr/lib/nginx/modules/ngx_stream_module.so;",
          "worker_processes 1;","error_log stderr crit;","pid /run/mnebyvpn-fi-route-canary.pid;",
          "events { worker_connections 128; }","stream {",
          "  map_hash_max_size 16384;","  map_hash_bucket_size 128;",
          "  map $ssl_preread_server_name $fi_upstream {","    hostnames;","    default \"\";"]
    for name in sorted(roots):rows.append("    ."+name+" $ssl_preread_server_name:443;")
    for name in exact:rows.append("    "+name+" $ssl_preread_server_name:443;")
    rows.extend(["  }","  resolver 1.1.1.1 1.0.0.1 ipv6=off valid=30s;","  resolver_timeout 4s;",
                 "  server {","    listen 127.0.0.1:14443;","    ssl_preread on;",
                 "    proxy_connect_timeout 5s;","    proxy_timeout 30s;",
                 "    proxy_pass $fi_upstream;","  }","}"])
    return "\n".join(rows)+"\n"

def compile_policy(source,base):
    policy=parse(source)
    return policy,render_core(policy,base),render_nginx(policy)

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit(2)
    # Raw common Corefile stays in the runner's protected temporary directory.
    # Only the domain catalog (no live server config or secret) crosses to FI.
    raw=Path(sys.argv[1]).read_bytes()
    p=parse(raw.decode("utf8"))
    p["source_sha256"]=hashlib.sha256(raw).hexdigest()
    Path(sys.argv[2]).write_text(json.dumps(p,separators=(",",":"),sort_keys=True)+"\n")
    print("FI_SHARED_ROUTE_SOURCE_EXACT="+str(len(p["exact"])))
    print("FI_SHARED_ROUTE_SOURCE_FAMILIES="+str(len(p["families"])))
