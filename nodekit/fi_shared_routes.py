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
from re import _parser as regex_parser, _constants as rx
import sys
from pathlib import Path

DE="89.125.90.101"
FI="217.11.167.91"
MAX_ROUTES=8192
HOST=re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
A_BLOCK=re.compile(r"(?ms)^([ \t]*)template[ \t]+IN[ \t]+A[ \t]+(\S+)[ \t]+\{(.*?)^\1\}")
FAMILY_START="(?i)^(?:[a-z0-9-]+[.])*(?:"
FAMILY_END=")[.]$"
MIXED_START="(?i)^(?:(?:[a-z0-9-]+[.])*(?:"
MIXED_SEPARATOR=")|(?:"
MIXED_END="))[.]$"

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

def alternatives(body):
    values=[literal("^"+part+"[.]$") for part in body.split("|")]
    need(values and len(values)==len(set(values)),"duplicate_alternative")
    return set(values)

def _plain_nodes(nodes):
    # Capturing vs noncapturing groups must not change the route language.
    result=[]
    for op,arg in nodes:
        if op==rx.SUBPATTERN:
            _,add,remove,body=arg
            need(not add and not remove,"scoped_regex_flags")
            result.extend(_plain_nodes(body))
        else:result.append((op,arg))
    return result

def _label_chars(nodes):
    nodes=_plain_nodes(nodes)
    if len(nodes)!=1 or nodes[0][0]!=rx.IN:return False
    chars=set()
    for op,value in nodes[0][1]:
        if op==rx.LITERAL:chars.add(chr(value))
        elif op==rx.RANGE and 0<=value[0]<=value[1]<128:
            chars.update(map(chr,range(value[0],value[1]+1)))
        else:return False
    return chars==set("abcdefghijklmnopqrstuvwxyz0123456789-")

def _label_prefix(op,arg):
    if op!=rx.MAX_REPEAT:return False
    lo,hi,body=arg
    if lo!=0 or hi!=rx.MAXREPEAT:return False
    body=_plain_nodes(body)
    if len(body)!=2 or body[0][0]!=rx.MAX_REPEAT or body[1]!=(rx.LITERAL,46):return False
    a,b,chars=body[0][1]
    return a==1 and b in (63,rx.MAXREPEAT) and _label_chars(chars)

def _expand(nodes):
    """Expand only finite literal alternatives and a full DNS-label prefix.

    A sentinel represents zero or more complete DNS labels. No generic
    wildcard, arbitrary repetition, lookaround, backreferences or Unicode
    character classes may silently broaden the catalog.
    """
    values=[""]
    for op,arg in _plain_nodes(nodes):
        if op==rx.LITERAL and chr(arg) in "abcdefghijklmnopqrstuvwxyz0123456789-.":
            parts=[chr(arg)]
        elif op==rx.BRANCH:
            parts=[]
            for branch in arg[1]:
                parts.extend(_expand(branch))
                need(len(parts)<=MAX_ROUTES,"route_expansion_bound")
        elif op==rx.IN:
            # Python factors alternatives with identical length into IN.
            need(all(k==rx.LITERAL and chr(v) in "abcdefghijklmnopqrstuvwxyz0123456789-." for k,v in arg),"unsupported_literal_class")
            parts=[chr(v) for k,v in arg]
        elif _label_prefix(op,arg):parts=["*."]
        else:raise ValueError("unsupported_regex_operation")
        need(len(values)*len(parts)<=MAX_ROUTES,"route_expansion_bound")
        values=[left+right for left in values for right in parts]
        need(all(len(v)<=256 for v in values),"route_name_bound")
    return values

def decode_pattern(raw):
    pattern=raw.strip()
    if pattern.startswith('"') and pattern.endswith('"'):
        pattern=pattern[1:-1]
    need(len(pattern)<=200000 and pattern.isascii(),"pattern_size_or_encoding")
    try:tree=regex_parser.parse(pattern,re.ASCII)
    except (re.error,OverflowError,RecursionError) as exc:
        raise ValueError("invalid_regex_syntax") from exc
    need(not tree.state.flags & ~(re.ASCII|re.IGNORECASE),"unsupported_regex_flags")
    nodes=_plain_nodes(tree)
    need(len(nodes)>=3 and nodes[0]==(rx.AT,rx.AT_BEGINNING) and nodes[-1]==(rx.AT,rx.AT_END),"unanchored_route")
    exact=set();roots=set()
    for value in _expand(nodes[1:-1]):
        need(value.endswith("."),"missing_dns_root")
        body=value[:-1]
        if body.startswith("*."):roots.add(hostname(body[2:]))
        else:exact.add(hostname(body))
    need(exact or roots,"empty_route")
    return exact,roots

def parse(core):
    need(isinstance(core,str) and len(core)<=2_000_000,"source_size")
    need(not re.search(r"(?m)^\s*import\s+",core),"unexpanded_source_import")
    blocks=list(A_BLOCK.finditer(core))
    total=len(re.findall(r"(?m)^[ \t]*template[ \t]+IN[ \t]+A[ \t]+\S+[ \t]+\{",core))
    need(len(blocks)==total and total>=264,"source_a_template_coverage")
    exact=set();roots=set()
    failures=[]
    for block_index,m in enumerate(blocks):
        zone=m[2].rstrip(".") if m[2]!="." else "."
        matches=re.findall(r"(?m)^[ \t]*match[ \t]+(.+?)\s*$",m[3])
        answers=re.findall(r'(?m)^[ \t]*answer[ \t]+"{{ \.Name }} [0-9]+ IN A ([0-9.]+)"[ \t]*$',m[3])
        try:
            need(len(matches)==1 and answers==[DE],"unexpected_shared_A_template")
            # Fail on extra answer/rcode instead of silently omitting behavior.
            need(len(re.findall(r"(?m)^[ \t]*answer[ \t]+",m[3]))==1 and not re.search(r"(?m)^[ \t]*rcode[ \t]+",m[3]),"unsupported_shared_A_behavior")
            names,families=decode_pattern(matches[0])
            if zone!=".":
                need(not families and names=={hostname(zone)},"exact_zone_mismatch")
        except ValueError as exc:
            # Structural diagnostic only; no live hostnames or raw rules.
            pattern=matches[0] if len(matches)==1 else ""
            print("FI_SHARED_ROUTE_PARSE_ERROR="+json.dumps({
                "reason":str(exc),"block_index":block_index,
                "root_zone":zone==".","length":len(pattern),
                "alternatives":pattern.count("|"),"groups":pattern.count("("),
                "quoted":pattern.startswith('"'),"casefold":pattern.startswith("(?i)"),
                "repetition":any(x in pattern for x in ("*","+","?")),
                "escaped_dot":r"\." in pattern,"dot_class":"[.]" in pattern
            },sort_keys=True),file=sys.stderr,flush=True)
            failures.append(str(exc))
            continue
        exact.update(names)
        roots.update(families)
    need(not failures,"unsupported_source_rules_count_"+str(len(failures)))
    need(len(exact)>=262 and len(roots)>=75 and len(exact|roots)<=MAX_ROUTES,"source_catalog_bounds")
    return {"exact":sorted(exact),"families":sorted(roots)}

def covered(policy,name):
    return name in policy["exact"] or any(name==r or name.endswith("."+r) for r in policy["families"])

def render_core(policy,base):
    marker="  forward . tls://1.1.1.1 tls://1.0.0.1 {"
    need(base.count(marker)==1 and "tls://.:8853 {" in base and "  bind 127.0.0.1" in base,"private_base_drift")
    need("template IN " not in base,"private_base_already_routed")
    # CoreDNS v1.15.0 template/setup.go limits EACH match regex to
    # 10000 bytes. Keep a margin below that limit, with multiple match
    # directives in one template (OR), rather than one giant expression.
    def chunks(names,prefix,suffix):
        groups=[];parts=[];size=len(prefix)+len(suffix)
        for name in names:
            value=name.replace(".","[.]")
            extra=len(value)+bool(parts)
            if parts and size+extra>8000:
                groups.append(prefix+"|".join(parts)+suffix)
                parts=[];size=len(prefix)+len(suffix);extra=len(value)
            need(size+extra<=8000,"route_pattern_bound")
            parts.append(value);size+=extra
        if parts:groups.append(prefix+"|".join(parts)+suffix)
        return groups
    patterns=chunks(policy["exact"],"(?i)^(?:",")[.]$")
    patterns+=chunks(policy["families"],FAMILY_START,FAMILY_END)
    rows=[]
    for kind in ("A","AAAA","CNAME","HTTPS","SVCB"):
        rows.append("  template IN "+kind+" . {")
        rows.extend("    match "+pattern for pattern in patterns)
        rows.extend(['    answer "{{ .Name }} 30 IN A '+FI+'"' if kind=="A" else "    rcode NOERROR",
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
