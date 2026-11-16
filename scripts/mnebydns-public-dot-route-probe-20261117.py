#!/usr/bin/env python3
"""Read-only CA-verified public DNS-over-TLS probes. Never prints personal hostnames."""
import os
import socket
import ssl
import struct
import ipaddress

SERVER="89.125.90.101"
SNI=os.environ.get("MNEBY_PUBLIC_DOT_SNI","dns.mnebyvpn.site")
NAMES=(
"www.youtube.com","m.youtube.com","youtubei.googleapis.com",
"jnn-pa.googleapis.com","i.ytimg.com","rr1---sn-gxuo03g-ig3s.googlevideo.com",
"yt.be","withyoutube.com","youtubeeducation.com","youtubekids.com",
"gvt1.com","gvt2.com","gmail.com","www.google.com",
"mtalk.google.com","time.google.com",
)
def qbytes(name, rrtype):
    part=b"".join(bytes([len(t)])+t.encode("ascii") for t in name.split("."))+b"\0"
    return struct.pack("!HHHHHH",0x23ac,0x0100,1,0,0,0)+part+struct.pack("!HH",rrtype,1)
def parse_response(data):
    if len(data)<12:raise ValueError("short DNS response")
    ident,flags,qn,an,ns,ar=struct.unpack_from("!HHHHHH",data)
    if ident!=0x23ac:raise ValueError("incorrect DNS query id")
    p=12
    def name_at(offset):
        start=offset
        count=0
        while True:
            if start>=len(data) or count>130:raise ValueError("invalid compressed name")
            size=data[start]
            if size&0xc0==0xc0:
                if start+1>=len(data):raise ValueError("truncated pointer")
                return start+2
            if size==0:return start+1
            if size&0xc0:raise ValueError("unknown labels")
            start+=size+1;count+=1
    for _ in range(qn):
        p=name_at(p)+4
    addresses=[]
    for _ in range(min(an,200)):
        p=name_at(p)
        if p+10>len(data):raise ValueError("truncated RR")
        typ,cls,ttl,l=struct.unpack_from("!HHIH",data,p)
        p+=10
        if p+l>len(data):raise ValueError("truncated payload")
        if typ==1 and cls==1 and l==4:
            addresses.append(str(ipaddress.IPv4Address(data[p:p+4])))
        p+=l
    return {"rcode":flags&15,"answers":an,"a":addresses}
def query(name,rrtype):
    msg=qbytes(name,rrtype)
    with socket.create_connection((SERVER,853),timeout=7) as s:
        with ssl.create_default_context().wrap_socket(s,server_hostname=SNI) as tls:
            tls.settimeout(7)
            tls.sendall(struct.pack("!H",len(msg))+msg)
            b=tls.recv(2)
            if len(b)!=2:raise ValueError("missing response length")
            size=struct.unpack("!H",b)[0]
            data=b""
            while len(data)<size:
                chunk=tls.recv(size-len(data))
                if not chunk:raise ValueError("closed DNS response")
                data+=chunk
            return parse_response(data)
def main():
    print("PUBLIC_DOT_ENDPOINT_GENERIC_ONLY=true")
    try:
        for name in NAMES:
            vals={}
            for typ,label in ((1,"A"),(28,"AAAA"),(65,"HTTPS")):
                try: vals[label]=query(name,typ)
                except Exception as exc:
                    vals[label]={"error":type(exc).__name__}
            print("PUBLIC_DOT",name,
                  "A=",vals["A"],
                  "AAAA=",vals["AAAA"],
                  "HTTPS=",vals["HTTPS"],flush=True)
    except Exception as exc:
        print("PUBLIC_DOT_GLOBAL_FAILURE="+type(exc).__name__,flush=True)
    print("PUBLIC_DOT_PERSONAL_AUTH_NOT_VALIDATED=true",flush=True)
if __name__=="__main__":main()
