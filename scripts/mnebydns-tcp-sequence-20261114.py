#!/usr/bin/env python3
"""Synthetic TCP sequence & receive-window observer, no packet storage.

Prints only relative TCP sequence and ACK positions, windows, payload lengths.
Observes solely GitHub runner's own traffic to/from RU188 public TCP443.
No IPs, user content, or raw packet dumps in output.
"""
import collections
import datetime
import socket
import ssl
import struct
import sys
import time

RU="188.120.254.223"
CONTROL=b"www.youtube.com"
MEDIA=b"rr1---sn-gxuo03g-ig3s.googlevideo.com"

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")

def watch(role, runner_ip, seconds):
    if role not in ("RUNNER","RU"): raise ValueError("bad role")
    packet=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0003))
    packet.settimeout(.25)
    end=time.monotonic()+seconds
    flows={}
    bases={}
    counts=collections.Counter()
    print("WATCH_READY",role,now(),flush=True)
    while time.monotonic()<end:
        try:p,info=packet.recvfrom(10000)
        except socket.timeout:continue
        if len(p)<40 or p[0]>>4!=4 or p[9]!=6:continue
        ihl=(p[0]&15)*4
        if ihl<20 or len(p)<ihl+20:continue
        if struct.unpack_from("!H",p,6)[0]&0x3fff:continue
        src=socket.inet_ntoa(p[12:16]);dst=socket.inet_ntoa(p[16:20])
        d=p[ihl:];sport,dport=struct.unpack_from("!HH",d)
        if role=="RUNNER":
            if dst==RU and dport==443:
                direction="CLIENT_TO_RU";flow=sport
            elif src==RU and sport==443:
                direction="RU_TO_CLIENT";flow=dport
            else:continue
        else:
            if info[0]!="ens3":continue
            if src==runner_ip and dst==RU and dport==443:
                direction="CLIENT_TO_RU";flow=sport
            elif dst==runner_ip and src==RU and sport==443:
                direction="RU_TO_CLIENT";flow=dport
            else:continue
        if flow not in flows:flows[flow]=len(flows)+1
        number=flows[flow]
        offset=((d[12]>>4)&15)*4
        if offset<20 or len(d)<offset:continue
        payload=d[offset:];seq,ack=struct.unpack_from("!II",d,4)
        win=struct.unpack_from("!H",d,14)[0]
        f=d[13]
        flags="".join(letter for bit,letter in ((2,"S"),(16,"A"),(8,"P"),(4,"R"),(1,"F")) if f&bit)
        key=(flow,direction)
        reverse="RU_TO_CLIENT" if direction=="CLIENT_TO_RU" else "CLIENT_TO_RU"
        if f&2:bases.setdefault(key,seq)
        if key not in bases and len(payload):bases[key]=seq-1
        rel=((seq-bases[key])&0xffffffff) if key in bases else None
        ackbase=bases.get((flow,reverse))
        ackrel=((ack-ackbase)&0xffffffff) if ackbase is not None else None
        hello="M" if MEDIA in payload else ("C" if CONTROL in payload else "-")
        tls_len=int.from_bytes(payload[3:5],"big")+5 if len(payload)>=5 and payload[:2]==b"\x16\x03" else None
        counts[(number,direction,"segments")]+=1
        counts[(number,direction,"data_bytes")]+=len(payload)
        print("TCP",role,now(),"FLOW",number,direction,"FLAGS",flags,"SEQ_REL",rel,"ACK_REL",ackrel,"WIN",win,"LEN",len(payload),"HELLO",hello,"TLS_RECORD_TOTAL",tls_len,flush=True)
    packet.close()
    print("WATCH_END",role,now(),flush=True)
    for k,v in sorted(counts.items()):
        print("TOTAL",role,*k,v,flush=True)

def client():
    for host in ("www.youtube.com","rr1---sn-gxuo03g-ig3s.googlevideo.com"):
        print("CLIENT_START",host,now(),flush=True)
        t=time.monotonic()
        try:
            with socket.create_connection((RU,443),timeout=5) as s:
                print("CLIENT_TCP_OK",host,round((time.monotonic()-t)*1000),now(),flush=True)
                s.settimeout(8)
                with ssl.create_default_context().wrap_socket(s,server_hostname=host) as ss:
                    print("CLIENT_TLS_OK",host,round((time.monotonic()-t)*1000),ss.version(),now(),flush=True)
        except Exception as e:print("CLIENT_TLS_FAILED",host,type(e).__name__,round((time.monotonic()-t)*1000),now(),flush=True)
        time.sleep(2)
if __name__=="__main__":
    if len(sys.argv)>1 and sys.argv[1]=="watch":watch(sys.argv[2],sys.argv[3],int(sys.argv[4]))
    elif len(sys.argv)>1 and sys.argv[1]=="client":client()
    else:raise SystemExit(2)
