#!/usr/bin/env python3
"""Fail-closed MNEBYDNS CoreDNS policy preservation and bounded DoT smoke probes.

No secrets, client identifiers or DNS payloads are logged by this module.
"""
from __future__ import annotations
from collections import Counter
import ipaddress
import re
import socket
import ssl
import struct
import secrets

TEMPLATE = re.compile(r"(?ms)^([ \t]*)template IN (A|AAAA|CNAME|HTTPS|SVCB) (\S+) \{(.*?)^\1\}")
CRITICAL = re.compile(r"(?m)^\s*(?:tls|bind|import|forward|reload|acl|hosts)\s+[^\n]+$")
OWNER = re.compile(r"(?i)MNEBYDNS OWNER DOMAIN")
GOOGLE_ROOTS = ("google.com","google.ru","google.de","google.co.uk",
                "googleapis.com","googlevideo.com","googleusercontent.com",
                "youtube.com","youtube-nocookie.com","ytimg.com","ggpht.com",
                "gstatic.com","withgoogle.com","googletagmanager.com")
GOOGLE_TOKEN = re.compile(r"(?i)(?:googlevideo|googleapis|googleusercontent|google|youtube|ytimg|ggpht|gstatic|withgoogle)")

def is_google_template(zone: str, raw: str) -> bool:
    if OWNER.search(raw) or "dns.mnebyvpn.site" in raw:
        return False
    if zone==".":
        # Google-family wildcard: only the known router's broad Google pattern.
        return bool(GOOGLE_TOKEN.search(raw))
    normalized=zone.rstrip(".").lower()
    return any(normalized==root or normalized.endswith("."+root) for root in GOOGLE_ROOTS)
RESOLVER_BIND = "89.125.90.101"
PIN = "188.120.254.223"
DOT_TLS_NAME = "dns.mnebyvpn.site"
# All known to be SmartDNS-synthetic at the verified initial release.
PROTECTED_A = ("www.youtube.com", "gemini.google.com",
               "www.google.com", "generativelanguage.googleapis.com",
               "claude.ai", "grok.com", "x.com", "www.tiktok.com")


def blocks(content: str):
    result=[(m.group(2),m.group(3),m.group(0)) for m in TEMPLATE.finditer(content)]
    # Reject partial/malformed parsing: an omitted unmatched template must
    # never be silently ignored when protecting existing customer routes.
    total=len(re.findall(r"(?m)^\s*template IN \S+ \S+ \{",content))
    if not result or total!=len(result):
        raise ValueError("Corefile template parser did not cover every route")
    return result


def preserved(old: bytes,new: bytes,scope: str="additive",owner_domain: str|None=None):
    """Preserve every pre-existing protected template, not just header names.

    scope=google permits changing only template blocks clearly containing Google
    families; all other blocks including personalized routes remain immutable.
    scope=owner permits one explicit domain block change from existing owner
    renderer; its unrelated template blocks must remain unchanged.
    """
    if scope not in ("additive","google","owner"):
        raise ValueError("Unknown DNS policy change scope")
    a,b=old.decode("utf-8"),new.decode("utf-8")
    oldblocks,newblocks=blocks(a),blocks(b)
    missing=Counter(oldblocks)-Counter(newblocks)
    for kind,zone,raw in missing.elements():
        if scope=="google" and is_google_template(zone,raw):
            continue
        if scope=="owner" and owner_domain and re.search(r"(?i)"+re.escape(owner_domain),raw):
            continue
        raise ValueError("Unapproved deletion/change of an existing DNS template")
    old_critical=Counter(line.strip() for line in CRITICAL.findall(
        TEMPLATE.sub("",a)))
    new_critical=Counter(line.strip() for line in CRITICAL.findall(
        TEMPLATE.sub("",b)))
    if old_critical-new_critical:
        raise ValueError("Protected DNS bind/TLS/import/forward/reload directive removed")
    for name in ("reload 5s 1s",):
        if name in a and name not in b:
            raise ValueError("CoreDNS hot reload disappeared")
    return {"preserved":True,"scope":scope,
            "prior_templates":len(oldblocks),"candidate_templates":len(newblocks),
            "unchanged_templates":len(oldblocks)-sum(missing.values())}


def _recvn(sock,n):
    buf=bytearray()
    while len(buf)<n:
        data=sock.recv(n-len(buf))
        if not data:raise ConnectionError("Unexpected DoT EOF")
        buf.extend(data)
    return bytes(buf)


def dns_a(host: str,*,address: str=RESOLVER_BIND,timeout: float=4.0):
    """CA-verified DoT query to local DNS service, no third-party resolver."""
    if not re.fullmatch(r"[a-z0-9.-]{4,253}",host):
        raise ValueError("Invalid DNS probe name")
    qname=b"".join(bytes([len(s)])+s.encode("ascii") for s in host.split("."))+b"\0"
    qid=secrets.randbits(16)
    msg=struct.pack("!HHHHHH",qid,0x100,1,0,0,0)+qname+struct.pack("!HH",1,1)
    with socket.create_connection((address,853),timeout=timeout) as conn:
        conn.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(conn,server_hostname=DOT_TLS_NAME) as tls:
            tls.sendall(struct.pack("!H",len(msg))+msg)
            size=struct.unpack("!H",_recvn(tls,2))[0]
            if not 12<=size<=4096:raise ValueError("Invalid DNS response size")
            resp=_recvn(tls,size)
    if int.from_bytes(resp[:2],"big")!=qid or resp[3]&15:
        raise ValueError("DoT transaction ID or response code failed")
    count=struct.unpack_from("!H",resp,6)[0]
    offset=12
    def skip_name(pos):
        for _ in range(128):
            n=resp[pos]
            if n&0xC0==0xC0:return pos+2
            if n==0:return pos+1
            pos+=1+n
        raise ValueError("Malformed DNS label")
    offset=skip_name(offset)+4
    ips=[]
    for _ in range(count):
        offset=skip_name(offset)
        typ,cls,ttl,rdlen=struct.unpack_from("!HHIH",resp,offset)
        offset+=10
        if offset+rdlen>len(resp):raise ValueError("Malformed DNS answer")
        if typ==1 and cls==1 and rdlen==4:
            ips.append(str(ipaddress.IPv4Address(resp[offset:offset+4])))
        offset+=rdlen
    return ips


def smoke_check(names=PROTECTED_A,*,resolver=dns_a):
    for host in names:
        values=resolver(host)
        if values != [PIN]:
            raise RuntimeError("Protected DNS synthetic A mismatch for "+host)
    return {"protected_hosts_checked":len(names),"resolver_bind":RESOLVER_BIND,
            "expected_ipv4":PIN,"all_pinned":True}
