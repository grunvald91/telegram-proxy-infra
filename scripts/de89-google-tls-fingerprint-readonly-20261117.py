#!/usr/bin/env python3
"""In-memory TLS prefix fingerprints across Nginx and GooglePilot on DE89.

Reads a small TLS record prefix from a 35-second streaming pcap, compares
salted hashes, and does NOT persist packet captures, TLS bytes, SNI, or IPs.
An observed match proves forwarded bytes, not application-level success.
"""
import collections
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import time

PUBLIC = "89.125.90.101"
LOCAL = "127.0.0.1"
MAX_SECONDS = 35
HASH_BYTES = 64

def read_exact(stream, n):
    chunks=[]
    left=n
    while left:
        part=stream.read(left)
        if not part:
            return None
        chunks.append(part)
        left-=len(part)
    return b"".join(chunks)

def global_header(stream):
    h=read_exact(stream,24)
    if not h:
        raise RuntimeError("PCAP_GLOBAL_HEADER_MISSING")
    options={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">",
             b"\x4d\x3c\xb2\xa1":"<",b"\xa1\xb2\x3c\x4d":">"}
    order=options.get(h[:4])
    if not order:
        raise RuntimeError("PCAP_NOT_CLASSIC")
    snap,linktype=struct.unpack(order+"II",h[16:24])
    if linktype not in (1,113,276):
        raise RuntimeError("PCAP_UNSUPPORTED_LINKTYPE_"+str(linktype))
    return order,linktype

def parse_frame(frame,linktype):
    if linktype==276:
        if len(frame)<20 or frame[:2]!=b"\x08\x00":return None
        off=20
    elif linktype==113:
        if len(frame)<16 or frame[14:16]!=b"\x08\x00":return None
        off=16
    else:
        if len(frame)<14 or frame[12:14]!=b"\x08\x00":return None
        off=14
    if len(frame)<off+20 or frame[off]>>4!=4:return None
    ihl=(frame[off]&15)*4
    if ihl<20 or len(frame)<off+ihl+20:return None
    if frame[off+9]!=6:return None
    frag=struct.unpack("!H",frame[off+6:off+8])[0]
    if (frag&0x1fff)!=0:return None
    total=struct.unpack("!H",frame[off+2:off+4])[0]
    src=socket.inet_ntoa(frame[off+12:off+16])
    dst=socket.inet_ntoa(frame[off+16:off+20])
    tcp=off+ihl
    sport,dport=struct.unpack("!HH",frame[tcp:tcp+4])
    tcp_hdr=(frame[tcp+12]>>4)*4
    if tcp_hdr<20 or len(frame)<tcp+tcp_hdr:return None
    size=max(0,total-ihl-tcp_hdr)
    data=frame[tcp+tcp_hdr:]
    return src,sport,dst,dport,size,data

def leg(src,sp,dst,dp):
    if dst==PUBLIC and dp==443:return "PUBLIC_CLIENT"
    if src==PUBLIC and sp==443:return "PUBLIC_SERVER"
    if src==LOCAL and dst==LOCAL and dp==15449:return "PILOT_CLIENT"
    if src==LOCAL and dst==LOCAL and sp==15449:return "PILOT_SERVER"
    if dp==443:return "UPSTREAM_CLIENT"
    if sp==443:return "UPSTREAM_SERVER"
    return None

def tls_kind(data):
    if len(data)<HASH_BYTES or data[0]!=22 or data[1]!=3:
        return None
    if data[5]==1:return "CLIENT_HELLO"
    if data[5]==2:return "SERVER_HELLO"
    return None

def run():
    if os.geteuid()!=0:raise RuntimeError("TRACE_REQUIRES_ROOT")
    secret=os.urandom(32)
    filt="tcp and ((host "+PUBLIC+" and port 443) or (host "+LOCAL+" and port 15449))"
    cmd=["timeout",str(MAX_SECONDS),"tcpdump","-i","any","-n","-U",
         "-s","256","-w","-",filt]
    print("FINGERPRINT_IN_MEMORY_ONLY=true",flush=True)
    print("FINGERPRINT_CAPTURE_SECONDS="+str(MAX_SECONDS),flush=True)
    print("FINGERPRINT_CAPTURE_PREFIX_BYTES="+str(HASH_BYTES),flush=True)
    print("FINGERPRINT_ARMED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    counts=collections.Counter()
    prefixes=collections.defaultdict(lambda:collections.Counter())
    matched=collections.defaultdict(dict)
    flow_response=collections.Counter()
    frames=0
    try:
        endian,link=global_header(p.stdout)
        print("FINGERPRINT_LINKTYPE="+str(link),flush=True)
        while True:
            hdr=read_exact(p.stdout,16)
            if hdr is None:break
            sec,sub,cap,orig=struct.unpack(endian+"IIII",hdr)
            if cap>4096:raise RuntimeError("PCAP_CAPTURE_LENGTH_OUT_OF_RANGE")
            frame=read_exact(p.stdout,cap)
            if frame is None:raise RuntimeError("PCAP_TRUNCATED_RECORD")
            frames+=1
            decoded=parse_frame(frame,link)
            if not decoded:continue
            src,sp,dst,dp,size,data=decoded
            layer=leg(src,sp,dst,dp)
            if not layer:continue
            counts[layer+"_PACKETS"]+=1
            if size:counts[layer+"_DATA_BYTES"]+=size
            if layer=="PUBLIC_SERVER" and size:
                flow_response[(dst,dp)]+=size
            kind=tls_kind(data)
            if not kind:continue
            digest=hmac.new(secret,data[:HASH_BYTES],hashlib.sha256).hexdigest()[:16]
            prefixes[(kind,digest)][layer]+=1
            if layer=="PUBLIC_CLIENT" and kind=="CLIENT_HELLO":
                matched[(kind,digest)]["public_flow"]=(src,sp)
            matched[(kind,digest)]["time"]=sec
    finally:
        p.wait(timeout=12)
    print("FINGERPRINT_FRAMES="+str(frames),flush=True)
    print("FINGERPRINT_CAPTURE_EXIT="+str(p.returncode),flush=True)
    for name in sorted(counts):
        print("FINGERPRINT_"+name+"="+str(counts[name]),flush=True)
    pub_candidates=0
    pilot_matched=0
    orphans=0
    for (kind,digest),where in sorted(prefixes.items()):
        if kind!="CLIENT_HELLO" or not where["PUBLIC_CLIENT"]:continue
        pub_candidates+=1
        matched_in_pilot=bool(where["PILOT_CLIENT"])
        if matched_in_pilot:pilot_matched+=1
        else:orphans+=1
        identity=matched[(kind,digest)].get("public_flow")
        response_bytes=flow_response.get(identity,0) if identity else 0
        # Digest is HMAC with an undisclosed one-time key.
        print("TLS_FLOW="+digest
              +" PUBLIC_CLIENT_HELLO="+str(where["PUBLIC_CLIENT"])
              +" PILOT_CLIENT_HELLO="+str(where["PILOT_CLIENT"])
              +" UPSTREAM_CLIENT_HELLO="+str(where["UPSTREAM_CLIENT"])
              +" PUBLIC_SERVER_BYTES="+str(response_bytes),flush=True)
    # Same ServerHello TLS prefix before public egress is direct evidence
    # for a corresponding raw TLS response. Missing matches are inconclusive
    # for packet splitting, injected fakes, or partial capture.
    pilot_server = [(digest,where) for (kind,digest),where in prefixes.items()
                    if kind=="SERVER_HELLO" and where["PILOT_SERVER"]]
    public_server = [(digest,where) for (kind,digest),where in prefixes.items()
                     if kind=="SERVER_HELLO" and where["PUBLIC_SERVER"]]
    both_server = [(digest,where) for digest,where in pilot_server
                   if where["PUBLIC_SERVER"]]
    print("SERVER_HELLO_PILOT_DISTINCT="+str(len(pilot_server)),flush=True)
    print("SERVER_HELLO_PUBLIC_DISTINCT="+str(len(public_server)),flush=True)
    print("SERVER_HELLO_PILOT_MATCHED_PUBLIC="+str(len(both_server)),flush=True)
    print("SERVER_HELLO_MATCH_IS_PREFIX_ONLY=true",flush=True)
    print("CLIENT_HELLO_PUBLIC_DISTINCT="+str(pub_candidates),flush=True)
    print("CLIENT_HELLO_PILOT_MATCHED="+str(pilot_matched),flush=True)
    print("CLIENT_HELLO_NO_PILOT_MATCH="+str(orphans),flush=True)
    print("CLIENT_HELLO_FINGERPRINT_ONLY_NO_FLOW_PROOF_IF_SEGMENTED=true",flush=True)
    print("FINGERPRINT_FIREWALL_UNCHANGED=true",flush=True)
    if frames==0 or p.returncode not in (0,124):
        raise RuntimeError("FINGERPRINT_CAPTURE_FAILED")
    if not pub_candidates:
        raise RuntimeError("FINGERPRINT_CONTROL_CLIENTHELLO_NOT_SEEN")

if __name__=="__main__":
    run()
