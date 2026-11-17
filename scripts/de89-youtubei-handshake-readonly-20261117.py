#!/usr/bin/env python3
"""Focused, temporary, read-only youtubei.googleapis.com TCP/TLS diagnostic.

Packet data is kept in RAM only. Logs never include packet payloads, full SNI
strings, raw client IPs/ports or TLS keys. Shows whether the expected TLS
record was fully received, forwarded, or answered for one TCP 4-tuple.
"""
import collections
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import time

TARGET = "youtubei.googleapis.com"
PUBLIC = "89.125.90.101"
LOOP = "127.0.0.1"
CAPTURE_SECONDS = 110
HASH_BYTES = 64
MAX_SEGMENTS = 24

def read_exact(file, size):
    data=bytearray()
    while len(data)<size:
        piece=file.read(size-len(data))
        if not piece:return None
        data.extend(piece)
    return bytes(data)

def read_header(file):
    data=read_exact(file,24)
    if not data:raise RuntimeError("MISSING_PCAP_HEADER")
    formats={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">",
             b"\x4d\x3c\xb2\xa1":"<",b"\xa1\xb2\x3c\x4d":">"}
    end=formats.get(data[:4])
    if not end:raise RuntimeError("UNSUPPORTED_PCAP_FORMAT")
    network=struct.unpack(end+"I",data[20:24])[0]
    if network not in (1,113,276):raise RuntimeError("UNSUPPORTED_LINKTYPE")
    return end,network

def decode(frame,network):
    if network==276:
        if len(frame)<20 or frame[:2]!=b"\x08\x00":return None
        offset=20
    elif network==113:
        if len(frame)<16 or frame[14:16]!=b"\x08\x00":return None
        offset=16
    else:
        if len(frame)<14 or frame[12:14]!=b"\x08\x00":return None
        offset=14
    if len(frame)<offset+40 or frame[offset]>>4!=4:return None
    ihl=(frame[offset]&0xf)*4
    if ihl<20 or len(frame)<offset+ihl+20:return None
    if frame[offset+9]!=6:return None
    frag=struct.unpack("!H",frame[offset+6:offset+8])[0]
    if frag&0x1fff:return None
    total=struct.unpack("!H",frame[offset+2:offset+4])[0]
    src=socket.inet_ntoa(frame[offset+12:offset+16])
    dst=socket.inet_ntoa(frame[offset+16:offset+20])
    p=offset+ihl
    sp,dp,seq=struct.unpack("!HHI",frame[p:p+8])
    tcp_len=(frame[p+12]>>4)*4
    if tcp_len<20 or len(frame)<p+tcp_len:return None
    flags=frame[p+13]
    window=struct.unpack("!H",frame[p+14:p+16])[0]
    body=frame[p+tcp_len:]
    plen=max(0,total-ihl-tcp_len)
    return src,sp,dst,dp,seq,flags,window,plen,body

def tls_sni(data):
    """Return SNI string, empty string when complete with none, or None."""
    if len(data)<9 or data[0]!=22 or data[1]!=3 or data[5]!=1:
        return None
    # TLS Handshake.ClientHello with 3-byte handshake length.
    p=9
    if len(data)<p+34:return None
    p+=34
    if len(data)<p+1:return None
    p+=1+data[p]
    if len(data)<p+2:return None
    size=int.from_bytes(data[p:p+2],"big")
    p+=2+size
    if len(data)<p+1:return None
    p+=1+data[p]
    if len(data)<p+2:return None
    ext_len=int.from_bytes(data[p:p+2],"big")
    p+=2
    if len(data)<p+ext_len:
        # We can still safely parse extensions already present.
        complete=False
    else:
        complete=True
    end=p+ext_len
    while p+4<=min(end,len(data)):
        t=int.from_bytes(data[p:p+2],"big")
        n=int.from_bytes(data[p+2:p+4],"big")
        p+=4
        if p+n>len(data):return None
        if t==0:
            content=data[p:p+n]
            if len(content)<5:return None
            list_len=int.from_bytes(content[:2],"big")
            if content[2]!=0:return None
            host_len=int.from_bytes(content[3:5],"big")
            if 5+host_len>len(content) or list_len>len(content)-2:return None
            return content[5:5+host_len].decode("ascii","ignore").lower()
        p+=n
    return "" if complete else None

def join_segments(segments):
    if not segments:return b""
    pairs=sorted(segments.items())
    result=bytearray()
    end=pairs[0][0]
    for seq,body in pairs:
        if seq>end:break
        off=end-seq
        if off<len(body):
            result.extend(body[off:])
            end+=len(body)-off
            if len(result)>=4096:break
    return bytes(result[:4096])

def run():
    if os.geteuid()!=0:raise RuntimeError("ROOT_REQUIRED")
    salt=os.urandom(32)
    filt="tcp and ((host "+PUBLIC+" and port 443) or (host "+LOOP+" and port 15449))"
    cmd=["timeout",str(CAPTURE_SECONDS),"tcpdump","-i","any","-n","-U",
         "-s","2250","-w","-",filt]
    print("TARGET_CAPTURE_TYPE=YOUTUBEI_TLS_ONLY",flush=True)
    print("TARGET_CAPTURE_NO_PERSISTENT_PACKETS=true",flush=True)
    print("TARGET_CAPTURE_SECONDS="+str(CAPTURE_SECONDS),flush=True)
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    public=collections.defaultdict(lambda:{"chunks":{},"server_bytes":0,"synack_win":None,
          "first":None,"server_pkts":0,"client_packets":0,"synack":0})
    pilot_hash=set()
    frames=0
    print("TARGET_CAPTURE_ARMED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    try:
        endian,link=read_header(proc.stdout)
        print("TARGET_CAPTURE_LINKTYPE="+str(link),flush=True)
        while True:
            h=read_exact(proc.stdout,16)
            if h is None:break
            sec,usec,cap,orig=struct.unpack(endian+"IIII",h)
            if cap>65535:raise RuntimeError("PCAP_OVERSIZED_RECORD")
            data=read_exact(proc.stdout,cap)
            if data is None:raise RuntimeError("PCAP_PARTIAL_RECORD")
            frames+=1
            pkt=decode(data,link)
            if pkt is None:continue
            src,sp,dst,dp,seq,flags,window,plen,body=pkt
            if dst==PUBLIC and dp==443:
                entry=public[(src,sp)]
                if plen:
                    entry["client_packets"]+=1
                    if entry["first"] is None:entry["first"]=sec+usec/1000000
                    if len(entry["chunks"])<MAX_SEGMENTS:
                        entry["chunks"][seq]=bytes(body)
            elif src==PUBLIC and sp==443:
                entry=public[(dst,dp)]
                if flags&2 and flags&16:
                    entry["synack"]+=1
                    entry["synack_win"]=window
                if plen:
                    entry["server_bytes"]+=plen
                    entry["server_pkts"]+=1
            elif src==LOOP and dst==LOOP and dp==15449:
                if len(body)>=HASH_BYTES and body[:1]==b"\x16" and body[5:6]==b"\x01":
                    pilot_hash.add(hmac.new(salt,body[:HASH_BYTES],hashlib.sha256).digest())
    finally:
        try:rc=proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc=proc.wait()
    print("TARGET_CAPTURE_FINISHED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    print("TARGET_CAPTURE_FRAMES="+str(frames),flush=True)
    print("TARGET_CAPTURE_EXIT="+str(rc),flush=True)
    target_count=0
    unknown_count=0
    all_no_reply=0
    for key,item in public.items():
        whole=join_segments(item["chunks"])
        if not whole:continue
        if whole[0]!=22 or len(whole)<9 or whole[5]!=1:continue
        name=tls_sni(whole)
        if not item["server_bytes"]:all_no_reply+=1
        if name is None:
            unknown_count+=1
            continue
        if name!=TARGET:continue
        target_count+=1
        expected=5+int.from_bytes(whole[3:5],"big")
        digest=hmac.new(salt,whole[:HASH_BYTES],hashlib.sha256).digest()
        ident=hmac.new(salt,repr(key).encode(),hashlib.sha256).hexdigest()[:10]
        forwarded=digest in pilot_hash
        print("YOUTUBEI_FLOW_ID="+ident
              +" CLIENT_TLS_RECORD_BYTES="+str(expected)
              +" CLIENT_REASSEMBLED_BYTES="+str(len(whole))
              +" CLIENT_SEGMENT_COUNT="+str(len(item["chunks"]))
              +" CLIENT_HELLO_COMPLETE="+str(len(whole)>=expected).lower()
              +" PILOT_CLIENT_PREFIX_MATCH="+str(forwarded).lower()
              +" PUBLIC_RESPONSE_BYTES="+str(item["server_bytes"])
              +" PUBLIC_RESPONSE_PKTS="+str(item["server_pkts"])
              +" SYNACK_COUNT="+str(item["synack"])
              +" SYNACK_ADVERTISED_WINDOW="+str(item["synack_win"]),flush=True)
    other_sni_no_reply=0
    incomplete_no_reply=0
    complete_no_reply=0
    unreadable_no_reply=0
    first_segment_1448_no_reply=0
    for key,item in public.items():
        whole=join_segments(item["chunks"])
        if len(whole)<9 or whole[0]!=22 or whole[5]!=1:continue
        if item["server_bytes"]:continue
        needed=5+int.from_bytes(whole[3:5],"big")
        if len(whole)<needed:incomplete_no_reply+=1
        else:complete_no_reply+=1
        if len(whole)==1448:first_segment_1448_no_reply+=1
        if tls_sni(whole) is None:unreadable_no_reply+=1
        elif tls_sni(whole)!=TARGET:other_sni_no_reply+=1
    print("NO_RESPONSE_TLS_RECORD_INCOMPLETE="+str(incomplete_no_reply),flush=True)
    print("NO_RESPONSE_TLS_RECORD_COMPLETE="+str(complete_no_reply),flush=True)
    print("NO_RESPONSE_TLS_RECEIVED_EXACTLY_1448="+str(first_segment_1448_no_reply),flush=True)
    print("NO_RESPONSE_TLS_SNI_UNREADABLE="+str(unreadable_no_reply),flush=True)
    print("NO_RESPONSE_TLS_OTHER_SNI="+str(other_sni_no_reply),flush=True)
    print("YOUTUBEI_IDENTIFIED_FLOWS="+str(target_count),flush=True)
    print("TLS_SNI_INCOMPLETE_OR_UNRECOGNIZED_FLOWS="+str(unknown_count),flush=True)
    print("PUBLIC_TLS_CLIENT_NO_RESPONSE_FLOWS="+str(all_no_reply),flush=True)
    print("TARGET_CAPTURE_NO_SERVER_CHANGES=true",flush=True)
    if not frames or rc not in (0,124):
        raise RuntimeError("TARGET_CAPTURE_NOT_VALID")

if __name__=="__main__":
    run()
