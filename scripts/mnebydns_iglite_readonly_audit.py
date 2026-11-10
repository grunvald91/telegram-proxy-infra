#!/usr/bin/env python3
"""READ ONLY: compare public resolver, active MNEBYDNS DoT and TLS SNI ingress.

No DNS route, firewall, reverse proxy, or service changes; no secrets logged.
All socket timeouts are bounded and errors remain explicit.
"""
from __future__ import annotations
import ipaddress
import os
import socket
import ssl
import struct
import sys
import time

DNS_IP="89.125.90.101"
DNS_SNI="dns.mnebyvpn.site"
RU_IP="188.120.254.223"
LITE_IP_SEEN_IN_PCAP="57.144.244.32"
HOSTS=["iglite-z.instagram.com","www.instagram.com","instagram.com","www.threads.net"]

def question(host:str,qtype:int,ident:int)->bytes:
    wire=b"".join(bytes([len(part)])+part.encode("ascii") for part in host.split("."))+b"\x00"
    return struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+wire+struct.pack("!HH",qtype,1)

def parse_name(data:bytes,off:int):
    labels=[];ret=None
    for _ in range(25):
        if off>=len(data):raise ValueError("DNS name exceeds message")
        n=data[off]
        if n&0xC0==0xC0:
            if off+1>=len(data):raise ValueError("truncated DNS pointer")
            if ret is None:ret=off+2
            off=((n&0x3f)<<8)|data[off+1]
            continue
        if n&0xc0 or n>63:raise ValueError("bad DNS name")
        off+=1
        if n==0:
            return ".".join(labels),(ret if ret is not None else off)
        if off+n>len(data):raise ValueError("truncated DNS label")
        labels.append(data[off:off+n].decode("ascii","replace"))
        off+=n
    raise ValueError("DNS compression loop")

def parse_dns(data:bytes):
    if len(data)<12:raise ValueError("truncated response")
    ident,flags,qd,an,ns,ar=struct.unpack("!HHHHHH",data[:12])
    pos=12
    for _ in range(qd):
        _,pos=parse_name(data,pos)
        pos+=4
    answers=[]
    for _ in range(an):
        name,pos=parse_name(data,pos)
        typ,cl,ttl,length=struct.unpack_from("!HHIH",data,pos)
        pos+=10
        raw=data[pos:pos+length];pos+=length
        if typ==1 and len(raw)==4:answers.append(("A",str(ipaddress.IPv4Address(raw))))
        elif typ==28 and len(raw)==16:answers.append(("AAAA",str(ipaddress.IPv6Address(raw))))
        elif typ==5:
            cname,_=parse_name(data,pos-length)
            answers.append(("CNAME",cname))
    return flags&15,answers

def recvall(tls,n:int)->bytes:
    chunks=[]
    while n:
        part=tls.recv(n)
        if not part:raise EOFError("DoT server closed")
        chunks.append(part)
        n-=len(part)
    return b"".join(chunks)

def query_dot(host:str,qtype:int):
    ident=int.from_bytes(os.urandom(2),"big")
    msg=question(host,qtype,ident)
    with socket.create_connection((DNS_IP,853),timeout=7) as sock:
        sock.settimeout(7)
        with ssl.create_default_context().wrap_socket(sock,server_hostname=DNS_SNI) as tls:
            tls.sendall(struct.pack("!H",len(msg))+msg)
            length=struct.unpack("!H",recvall(tls,2))[0]
            data=recvall(tls,length)
            if len(data)<2 or struct.unpack_from("!H",data)[0]!=ident:
                raise ValueError("DoT transaction ID mismatch")
            return parse_dns(data)

def public_ipv4(host:str):
    try:
        return sorted({v[4][0] for v in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)})
    except Exception as e:
        return ["ERROR_"+type(e).__name__]

def check_tls(ip:str,host:str):
    start=time.monotonic()
    try:
        with socket.create_connection((ip,443),timeout=6) as s:
            s.settimeout(6)
            elapsed_tcp=round(time.monotonic()-start,2)
            with ssl.create_default_context().wrap_socket(s,server_hostname=host) as tls:
                return f"tcp=PASS({elapsed_tcp}s) tls=VERIFIED version={tls.version()} alpn={tls.selected_alpn_protocol()}"
    except ssl.SSLCertVerificationError as e:
        return "tcp=PASS tls=CERTIFICATE_REJECTED_"+str(e.verify_code)
    except Exception as e:
        return "tcp_or_tls="+type(e).__name__+"("+str(e)[:85]+")"

def main():
    print("audit_scope=READ_ONLY",flush=True)
    for host in HOSTS:
        print("host="+host,flush=True)
        print("system_resolver_ipv4="+",".join(public_ipv4(host)),flush=True)
        for typ,label in [(1,"A"),(28,"AAAA")]:
            try:
                code,records=query_dot(host,typ)
                v=";".join(k+":"+value for k,value in records) or "NO_ANSWER"
                print("mnebydns_dot_"+label+"=rcode:"+str(code)+" "+v,flush=True)
            except Exception as e:
                print("mnebydns_dot_"+label+"=ERROR_"+type(e).__name__+":"+str(e)[:130],flush=True)
    for host,ip in [("iglite-z.instagram.com",RU_IP),
                    ("iglite-z.instagram.com",LITE_IP_SEEN_IN_PCAP)]:
        print("SNI_probe_host="+host+" dest="+ip+" "+check_tls(ip,host),flush=True)

if __name__=="__main__":
    main()
