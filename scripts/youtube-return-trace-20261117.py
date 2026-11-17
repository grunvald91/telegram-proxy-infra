#!/usr/bin/env python3
"""Focused, temporary, read-only *.googlevideo.com TCP ACK and TLS diagnostic.

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

TARGET_SUFFIX = (".googlevideo.com", ".youtube.com", ".ytimg.com", ".googleapis.com", ".ggpht.com", ".gstatic.com", ".googleusercontent.com")
PUBLIC = "89.125.90.101"
LOOP = "127.0.0.1"
CAPTURE_SECONDS = 90
# Retain at least the entire 4 KiB reassembly budget, even for a GRO frame.
CAPTURE_PREFIX_BYTES = 8192
REASSEMBLY_BYTES = 4096
HASH_BYTES = 64
MAX_SEGMENTS = 4096

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
    sp,dp,seq,ack=struct.unpack("!HHII",frame[p:p+12])
    tcp_len=(frame[p+12]>>4)*4
    if tcp_len<20 or len(frame)<p+tcp_len:return None
    flags=frame[p+13]
    window=struct.unpack("!H",frame[p+14:p+16])[0]
    body=frame[p+tcp_len:offset+total]
    plen=max(0,total-ihl-tcp_len)
    ifidx=struct.unpack("!I",frame[4:8])[0] if network==276 else -1
    pkttype=frame[10] if network==276 else -1
    return src,sp,dst,dp,seq,flags,window,plen,ack,ifidx,pkttype,body

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

def remember(chunks,seq,body):
    # A shorter retransmission must never erase bytes captured in a GRO packet.
    if chunks and seq >= min(chunks) + REASSEMBLY_BYTES and len(join_segments(chunks)) >= REASSEMBLY_BYTES:return
    previous=chunks.get(seq,b"")
    if seq not in chunks and len(chunks)>=MAX_SEGMENTS:return
    if len(body)>len(previous):chunks[seq]=bytes(body[:16384])

def run():
    if os.geteuid()!=0:raise RuntimeError("ROOT_REQUIRED")
    salt=os.urandom(32)
    filt="tcp and ((host "+PUBLIC+" and port 443) or (host "+LOOP+" and port 15449))"
    cmd=["timeout",str(CAPTURE_SECONDS),"tcpdump","-i","any","-n","-U",
         "-B","65536","-s","8192","-w","-",filt]
    print("TARGET_CAPTURE_TYPE=YOUTUBE_TLS_ONLY",flush=True)
    print("TARGET_CAPTURE_NO_PERSISTENT_PACKETS=true",flush=True)
    print("TARGET_CAPTURE_SECONDS="+str(CAPTURE_SECONDS),flush=True)
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    public=collections.defaultdict(lambda:{"chunks":{},"server_bytes":0,"synack_win":None,
          "first":None,"server_pkts":0,"client_packets":0,"synack":0,
          "pure_ack_events":[],"client_retransmissions":0,"server_first":None,"close":None,"zero_windows":0})
    wan_ifindex=socket.if_nametoindex("eth0")
    pilot_hash=set()
    pilot_server_hash=set()
    public_server_hash=set()
    pilot_chunks=collections.defaultdict(dict)
    origin_chunks=collections.defaultdict(dict)
    origin_bytes=collections.Counter()
    origin_first={}
    pilot_reply=collections.Counter()
    pilot_first={}
    truncated=0
    unsafe_prefixes=0
    frames=0
    print("TARGET_CAPTURE_ARMED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    try:
        endian,link=read_header(proc.stdout)
        print("TARGET_CAPTURE_LINKTYPE="+str(link),flush=True)
        ready=os.environ.get("MNEBY_CAPTURE_READY")
        if ready:
            with open(ready,"x") as f:f.write("ARMED\n")
        while True:
            h=read_exact(proc.stdout,16)
            if h is None:break
            sec,usec,cap,orig=struct.unpack(endian+"IIII",h)
            if cap>1048576:raise RuntimeError("PCAP_OVERSIZED_RECORD")
            data=read_exact(proc.stdout,cap)
            if data is None:raise RuntimeError("PCAP_PARTIAL_RECORD")
            frames+=1
            truncated+=int(cap<orig)
            if cap<orig and cap < REASSEMBLY_BYTES + 512:unsafe_prefixes+=1
            pkt=decode(data,link)
            if pkt is None:continue
            src,sp,dst,dp,seq,flags,window,plen,ack,ifidx,pkttype,body=pkt
            if dst==PUBLIC and dp==443:
                entry=public[(src,sp)]
                if window==0:entry["zero_windows"]+=1
                if flags&5 and entry["close"] is None:entry["close"]=sec+usec/1000000
                if plen:
                    entry["client_packets"]+=1
                    if entry["first"] is None:entry["first"]=sec+usec/1000000
                    if seq in entry["chunks"]:entry["client_retransmissions"]+=1
                    remember(entry["chunks"],seq,body)
            elif src==PUBLIC and sp==443:
                entry=public[(dst,dp)]
                if (flags&16) and not (flags&2) and plen==0 and ifidx==wan_ifindex and pkttype==4:
                    if len(entry["pure_ack_events"])<60:
                        entry["pure_ack_events"].append((ack,sec+usec/1000000,window))
                if flags&2 and flags&16:
                    entry["synack"]+=1
                    entry["synack_win"]=window
                if len(body)>=HASH_BYTES and body[:1]==b"\x16" and body[5:6]==b"\x02":
                    public_server_hash.add(hmac.new(salt,body[:HASH_BYTES],hashlib.sha256).digest())
                if plen:
                    if entry["server_first"] is None:entry["server_first"]=sec+usec/1000000
                    entry["server_bytes"]+=plen
                    entry["server_pkts"]+=1
            elif src==PUBLIC and dp==443 and dst!=PUBLIC:
                key=(dst,dp,sp)
                if plen:remember(origin_chunks[key],seq,body)
            elif dst==PUBLIC and sp==443 and dp!=443:
                origin_bytes[(src,sp,dp)]+=plen
                if plen:origin_first.setdefault((src,sp,dp),sec+usec/1000000)
            elif src==LOOP and dst==LOOP and dp==15449:
                if plen:remember(pilot_chunks[sp],seq,body)
                if len(body)>=HASH_BYTES and body[:1]==b"\x16" and body[5:6]==b"\x01":
                    pilot_hash.add(hmac.new(salt,body[:HASH_BYTES],hashlib.sha256).digest())
            elif src==LOOP and dst==LOOP and sp==15449:
                pilot_reply[dp]+=plen
                if plen:pilot_first.setdefault(dp,sec+usec/1000000)
                if len(body)>=HASH_BYTES and body[:1]==b"\x16" and body[5:6]==b"\x02":
                    pilot_server_hash.add(hmac.new(salt,body[:HASH_BYTES],hashlib.sha256).digest())
    finally:
        try:rc=proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc=proc.wait()
    capture_end=time.time()
    capture_stats=proc.stderr.read().decode("utf-8","replace")
    import re
    dropped=re.search(r"(\d+) packets dropped by kernel",capture_stats)
    print("CAPTURE_KERNEL_DROPS="+(dropped[1] if dropped else "UNKNOWN"),flush=True)
    print("CAPTURE_TRUNCATED_FRAMES="+str(truncated),flush=True)
    print("CAPTURE_PREFIX_BYTES="+str(CAPTURE_PREFIX_BYTES),flush=True)
    print("CAPTURE_UNSAFE_SHORT_PREFIXES="+str(unsafe_prefixes),flush=True)
    print("TARGET_CAPTURE_FINISHED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    print("TARGET_CAPTURE_FRAMES="+str(frames),flush=True)
    print("TARGET_CAPTURE_EXIT="+str(rc),flush=True)
    def complete_digest(chunks):
        data=join_segments(chunks)
        if len(data)<9 or data[0]!=22 or data[5]!=1:return None
        expected=5+int.from_bytes(data[3:5],"big")
        if len(data)<expected:return None
        return hmac.new(salt,data[:expected],hashlib.sha256).digest()
    pilot_complete={d for chunks in pilot_chunks.values() if (d:=complete_digest(chunks)) is not None}
    origin_complete={}
    for key,chunks in origin_chunks.items():
        d=complete_digest(chunks)
        if d is not None:origin_complete[d]=origin_bytes[key]
    pilot_returns={}
    for port,chunks in pilot_chunks.items():
        d=complete_digest(chunks)
        if d is not None:pilot_returns[d]=(pilot_reply[port],pilot_first.get(port))
    origin_times={}
    for key,chunks in origin_chunks.items():
        d=complete_digest(chunks)
        if d is not None:origin_times[d]=origin_first.get(key)
    target_count=0
    target_completed=0
    target_no_response=0
    target_forwarded=0
    target_large_response=0
    incomplete_acks_sent=0
    incomplete_acks_not_seen=0
    incomplete_first_ack_delay_count=0
    incomplete_client_retransmit=0
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
        if not (name=='googlevideo.com' or name.endswith(TARGET_SUFFIX)):continue
        target_count+=1
        expected=5+int.from_bytes(whole[3:5],"big")
        digest=hmac.new(salt,whole[:HASH_BYTES],hashlib.sha256).digest()
        ident=hmac.new(salt,repr(key).encode(),hashlib.sha256).hexdigest()[:10]
        forwarded=digest in pilot_hash
        target_completed+=int(len(whole)>=expected)
        target_no_response+=int(item["server_bytes"]==0)
        target_forwarded+=int(forwarded)
        target_large_response+=int(item["server_bytes"]>=65536)
        # ACK numbers are cumulative: count only pure outbound ACKs that
        # acknowledge every byte of the first client TCP segment.
        base_seq,first_payload_len=next(iter(sorted(
            (seq,len(segment)) for seq,segment in item["chunks"].items())))
        qualifying=[(when,win) for ack,when,win in item["pure_ack_events"]
            if item["first"] is not None and when>=item["first"]
            and first_payload_len <= ((ack-base_seq) & 0xffffffff) < (1<<31)]
        saw_ack=bool(qualifying)
        if len(whole)<expected and not item["server_bytes"]:
            incomplete_acks_sent+=int(saw_ack)
            incomplete_acks_not_seen+=int(not saw_ack)
            incomplete_first_ack_delay_count+=int(saw_ack and qualifying[0][0]-item["first"]>0.2)
            incomplete_client_retransmit+=int(item["client_retransmissions"]>0)
        client_id=hmac.new(salt,key[0].encode(),hashlib.sha256).hexdigest()[:10]
        full_digest=complete_digest(item["chunks"])
        group=next((suffix[1:] for suffix in TARGET_SUFFIX if name.endswith(suffix)),"root")
        def delay(stamp):
            return str(round((stamp-item["first"])*1000)) if stamp is not None else "NONE"
        pr=pilot_returns.get(full_digest,(0,None))
        print("YOUTUBE_FLOW_ID="+ident
              +" OBSERVED_AFTER_HELLO_MS="+delay(capture_end)
              +" ORIGIN_FIRST_RESPONSE_MS="+delay(origin_times.get(full_digest))
              +" PILOT_RESPONSE_BYTES="+str(pr[0])
              +" PILOT_FIRST_RESPONSE_MS="+delay(pr[1])
              +" PUBLIC_FIRST_RESPONSE_MS="+delay(item["server_first"])
              +" CLIENT_CLOSE_MS="+delay(item["close"])
              +" CLIENT_ZERO_WINDOW_EVENTS="+str(item["zero_windows"])
              +" CLIENT_ID="+client_id
              +" HOST_GROUP="+group
              +" FULL_HELLO_PILOT_MATCH="+str(full_digest in pilot_complete if full_digest else False).lower()
              +" FULL_HELLO_ORIGIN_MATCH="+str(full_digest in origin_complete if full_digest else False).lower()
              +" ORIGIN_RESPONSE_BYTES="+str(origin_complete.get(full_digest,0))
              +" CLIENT_TLS_RECORD_BYTES="+str(expected)
              +" CLIENT_REASSEMBLED_BYTES="+str(len(whole))
              +" CLIENT_SEGMENT_COUNT="+str(len(item["chunks"]))
              +" SEGMENT_RETENTION_LIMIT_REACHED="+str(len(item["chunks"])>=MAX_SEGMENTS).lower()
              +" CLIENT_HELLO_COMPLETE="+str(len(whole)>=expected).lower()
              +" PILOT_CLIENT_PREFIX_MATCH="+str(forwarded).lower()
              +" PUBLIC_RESPONSE_BYTES="+str(item["server_bytes"])
              +" PUBLIC_RESPONSE_PKTS="+str(item["server_pkts"])
              +" SYNACK_COUNT="+str(item["synack"])
              +" SYNACK_ADVERTISED_WINDOW="+str(item["synack_win"])
              +" SERVER_WAN_ACK_COVERS_FULL_TLS_RECORD="+str(any(expected <= ((ack-base_seq) & 0xffffffff) < (1<<31) for ack,when,win in item["pure_ack_events"] if when>=item["first"])).lower()
              +" TLS_RECORD_WITHIN_REASSEMBLY_BUDGET="+str(expected<=REASSEMBLY_BYTES).lower()
              +" PURE_WAN_ACK_SEEN="+str(saw_ack).lower()
              +" PURE_WAN_ACK_EVENTS="+str(len(item["pure_ack_events"]))
              +" FIRST_ACK_DELAY_MS="+(str(round((qualifying[0][0]-item["first"])*1000))
                  if qualifying else "NONE")
              +" FIRST_TCP_SEGMENT_BYTES="+str(first_payload_len)
              +" CLIENT_RETRANSMIT_PACKETS="+str(item["client_retransmissions"]),flush=True)
    print("YOUTUBE_CLIENT_HELLO_FULL_COUNT="+str(target_completed),flush=True)
    print("YOUTUBE_CLIENT_HELLO_TO_PILOT_MATCH_COUNT="+str(target_forwarded),flush=True)
    print("YOUTUBE_NO_PUBLIC_RESPONSE_COUNT="+str(target_no_response),flush=True)
    print("YOUTUBE_INCOMPLETE_NO_RESPONSE_WITH_ACK="+str(incomplete_acks_sent),flush=True)
    print("YOUTUBE_INCOMPLETE_NO_RESPONSE_WITHOUT_ACK="+str(incomplete_acks_not_seen),flush=True)
    print("YOUTUBE_INCOMPLETE_FIRST_ACK_OVER_200MS="+str(incomplete_first_ack_delay_count),flush=True)
    print("YOUTUBE_INCOMPLETE_CLIENT_RETRANSMITTED="+str(incomplete_client_retransmit),flush=True)
    print("YOUTUBE_ACK_AT_ETH0_NOT_PROOF_OF_PHONE_DELIVERY=true",flush=True)
    print("YOUTUBE_PUBLIC_RESPONSE_OVER_64K_COUNT="+str(target_large_response),flush=True)
    print("YOUTUBE_PILOT_SERVERHELLO_PUBLIC_MATCH_COUNT="+str(len(pilot_server_hash & public_server_hash)),flush=True)
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
        elif not (tls_sni(whole)=="googlevideo.com" or tls_sni(whole).endswith(TARGET_SUFFIX)):other_sni_no_reply+=1
    print("NO_RESPONSE_TLS_RECORD_INCOMPLETE="+str(incomplete_no_reply),flush=True)
    print("NO_RESPONSE_TLS_RECORD_COMPLETE="+str(complete_no_reply),flush=True)
    print("NO_RESPONSE_TLS_RECEIVED_EXACTLY_1448="+str(first_segment_1448_no_reply),flush=True)
    print("NO_RESPONSE_TLS_SNI_UNREADABLE="+str(unreadable_no_reply),flush=True)
    print("NO_RESPONSE_TLS_OTHER_SNI="+str(other_sni_no_reply),flush=True)
    print("YOUTUBE_IDENTIFIED_FLOWS="+str(target_count),flush=True)
    print("YOUTUBE_FLOW_TO_PHONE_MAPPING=NOT_PROVEN_WITHOUT_SINGULAR_PLAYBACK",flush=True)
    print("TLS_SNI_INCOMPLETE_OR_UNRECOGNIZED_FLOWS="+str(unknown_count),flush=True)
    print("PUBLIC_TLS_CLIENT_NO_RESPONSE_FLOWS="+str(all_no_reply),flush=True)
    print("TARGET_CAPTURE_NO_SERVER_CHANGES=true",flush=True)
    if dropped is None or int(dropped[1])!=0 or unsafe_prefixes:
        raise RuntimeError("CAPTURE_LOSS_OR_UNSAFE_PREFIX_INVALIDATES_ABSENCE_CLAIMS")
    if not frames or rc not in (0,124):
        raise RuntimeError("TARGET_CAPTURE_NOT_VALID")

if __name__=="__main__":
    run()
