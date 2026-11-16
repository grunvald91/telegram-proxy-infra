#!/usr/bin/env python3
"""MNEBYDNS 2026-11-16 read-only live comparison to 2026-11-08 Google canary.
No writes, restarts, configuration dumps, client identifiers, keys, or raw rules.
"""
import datetime
import hashlib
import ipaddress
import json
import pathlib
import re
import socket
import ssl
import struct
import subprocess
import sys

ROLE = sys.argv[1] if len(sys.argv) > 1 else "DE"
if ROLE not in ("DE", "RU"):
    raise SystemExit("role must be DE or RU")
DE = "89.125.90.101"
RU = "188.120.254.223"
MEDIA = "rr1---sn-gxuo03g-ig3s.googlevideo.com"
def cmd(args, timeout=9):
    try:
        r = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return (r.returncode, r.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return (127, "")
def status(unit):
    code, out = cmd(["systemctl", "is-active", unit])
    return out.strip() if code == 0 else "inactive-or-unknown"
def sha(path):
    p = pathlib.Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def sni(ip, hostname, port=443, timeout=5):
    try:
        with socket.create_connection((ip,port),timeout=timeout) as tcp:
            tcp.settimeout(timeout)
            with ssl.create_default_context().wrap_socket(tcp, server_hostname=hostname) as conn:
                return {"ok":bool(conn.getpeercert()),"tls":conn.version()}
    except Exception as exc:
        return {"ok":False,"error":type(exc).__name__}
def readexact(sock,n):
    out=b""
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk: raise EOFError()
        out+=chunk
    return out
def skipname(data,pos):
    for _ in range(125):
        if pos>=len(data): raise ValueError("dns name overflow")
        n=data[pos]
        if n & 0xc0 == 0xc0: return pos+2
        if n==0: return pos+1
        if n & 0xc0: raise ValueError("invalid DNS label")
        pos+=n+1
    raise ValueError("dns name too long")
def dot(ip, hostname, qtype=1):
    try:
        labels=hostname.split(".")
        qname=b"".join(bytes([len(x)])+x.encode("ascii") for x in labels)+b"\x00"
        query=struct.pack("!HHHHHH",0x4A51,0x0100,1,0,0,0)+qname+struct.pack("!HH",qtype,1)
        with socket.create_connection((ip,853),timeout=5) as tcp:
            tcp.settimeout(5)
            with ssl.create_default_context().wrap_socket(tcp,server_hostname="dns.mnebyvpn.site") as tls:
                tls.sendall(struct.pack("!H",len(query))+query)
                size=struct.unpack("!H",readexact(tls,2))[0]
                data=readexact(tls,size)
        _,flags,qd,an,_,_=struct.unpack("!HHHHHH",data[:12])
        p=12
        for _ in range(qd):
            p=skipname(data,p)+4
        ips=[]
        for _ in range(an):
            p=skipname(data,p)
            typ,klass,ttl,length=struct.unpack("!HHIH",data[p:p+10]);p+=10
            if typ==1 and klass==1 and length==4:
                ips.append(str(ipaddress.IPv4Address(data[p:p+4])))
            p+=length
        return {"ok":(flags & 15)==0,"rcode":flags & 15,"A":sorted(set(ips)) if qtype==1 else [],"answers":an}
    except Exception as exc:
        return {"ok":False,"error":type(exc).__name__}
def config(path):
    p=pathlib.Path(path)
    if not p.is_file(): return {"exists":False}
    s=p.read_text(errors="replace")
    return {"exists":True,"sha256":sha(path),"size":len(s)}
def nginx_info(path):
    obj=config(path)
    if not obj["exists"]:return obj
    s=pathlib.Path(path).read_text(errors="replace")
    obj.update({
        "googlevideo_marker":bool(re.search(r"googlevideo(?:\[.\]|\.|\\\.)com",s,re.I)),
        "youtube_marker":"youtube.com" in s,
        "googlepilot_port_15449":"15449" in s,
        "ssl_preread":"ssl_preread on" in s or "ssl_preread  on" in s,
        "proxy_timeout_values":sorted(set(re.findall(r"proxy_timeout\s+(\d+[smh])\s*;",s))),
        "route_direct_de":DE in s,
        "route_via_ru":RU in s,
        "http3_or_alt_svc":bool(re.search(r"(?:\bhttp3\b|alt-svc)",s,re.I))
    })
    return obj
def coredns_info(path):
    obj=config(path)
    if not obj["exists"]:return obj
    s=pathlib.Path(path).read_text(errors="replace")
    obj.update({
        "target_de89_templates":len(re.findall(r'answer\s+"[^"]*\bIN\s+A\s+'+re.escape(DE)+r'\b',s)),
        "target_ru188_templates":len(re.findall(r'answer\s+"[^"]*\bIN\s+A\s+'+re.escape(RU)+r'\b',s)),
        "googlevideo_marker":bool(re.search(r'googlevideo(?:\[.\]|\.|\\\.)com',s,re.I)),
        "youtube_marker":"youtube.com" in s,
        "https_svcb_suppression_templates":len(re.findall(r'template\s+IN\s+(?:HTTPS|SVCB)\b',s))
    })
    return obj
def listeners():
    rc,t=cmd(["ss","-H","-lntu"],timeout=8)
    result={}
    for proto,port in (("tcp",443),("udp",443),("tcp",853),("tcp",15449),("udp",19444)):
        result[f"{proto}_{port}"]=bool(rc==0 and any(line.startswith(proto) and re.search(r"(?<!\d):"+str(port)+r"\b",line) for line in t.splitlines()))
    return result
def nft_status():
    rc,t=cmd(["nft","-j","list","table","inet","mnebydns_udp443_owner_exp_20261116"],timeout=7)
    if rc!=0:return {"experiment_table_present":False}
    try:
        arr=json.loads(t)["nftables"]
        return {"experiment_table_present":True,
                "reject_443_present":any("reject" in json.dumps(x) and '"443"' in json.dumps(x) for x in arr)}
    except Exception:
        return {"experiment_table_present":True,"parse_error":True}
def link_status():
    rc,t=cmd(["ip","-j","link","show","dev","tg-relay"],timeout=7)
    if rc:return {"tg_relay_exists":False}
    try:
        j=json.loads(t)[0]
        return {"tg_relay_exists":True,"operstate":j.get("operstate"),"mtu":j.get("mtu"),"kind":j.get("linkinfo",{}).get("info_kind")}
    except Exception:return {"tg_relay_exists":True}
out={"role":ROLE,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"read_only":True,
     "listeners":listeners(),
     "service_states":{name:status(name) for name in (
         ["nginx.service","mnebydns-dot.service","mnebydns-googlepilot.service",
          "mnebydns-de89-public-quic-20261115.service",
          "mnebydns-udp443-owner-exp-revert-20261116.timer"]
         if ROLE=="DE" else
         ["nginx.service","wg-quick@tg-relay.service","awg-quick@tg-relay.service"])},
     "tunnel":link_status()}
if ROLE=="DE":
    out["coredns"]=coredns_info("/opt/mnebydns-dot/Corefile")
    out["nginx_shared"]=nginx_info("/etc/nginx/nginx.conf")
    out["nginx_googlepilot"]=nginx_info("/etc/mnebydns-googlepilot/nginx.conf")
    out["udp_reject"]=nft_status()
    out["tls"]={f"googlepilot_127_15449_{h}":sni("127.0.0.1",h,15449) for h in ("www.youtube.com",MEDIA)}
    out["tls"]["de_public_443_youtube"]=sni(DE,"www.youtube.com")
else:
    out["dns"]={h:dot(DE,h,1) for h in ("www.youtube.com","youtubei.googleapis.com","www.googlevideo.com","example.org")}
    out["dns"]["www_youtube_AAAA"]=dot(DE,"www.youtube.com",28)
    out["dns"]["www_youtube_HTTPS"]=dot(DE,"www.youtube.com",65)
    out["tls"]={f"{path}_{h}":sni(ip,h) for path,ip in (("de_public",DE),("wg_private","10.66.77.1"),("ru_public",RU)) for h in ("www.youtube.com",MEDIA)}
print(json.dumps(out,ensure_ascii=False,sort_keys=True))
