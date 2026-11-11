#!/usr/bin/env python3
"""In-memory TCP SNI boundary detector. Never writes PCAP, payload or peer IP.
Only parses Ethernet/IPv4 TCP flows reaching DE:443. Observed interface segments
are not proof of the sender's Android identity or the full Russian ISP path.
"""
from __future__ import annotations
from collections import Counter, OrderedDict
import re
import signal
import struct
import subprocess
import threading
import time

LIMIT=8192
FLOW_LIMIT=512
PACKET_LIMIT=1600

def u16(buf,i):
    if i+2>len(buf): raise ValueError('truncated')
    return int.from_bytes(buf[i:i+2],'big')

def locate_sni(record):
    data=bytes(record)
    if len(data)<9 or data[0]!=22 or data[1]!=3 or data[2]>4:
        return None
    size=5+u16(data,3)
    if size>LIMIT or len(data)<size or data[5]!=1:
        return None
    if int.from_bytes(data[6:9],'big')+4>size-5:
        return None
    try:
        at=9+2+32
        sid=data[at]
        at+=1+sid
        cipher=u16(data,at)
        at+=2+cipher
        compress=data[at]
        at+=1+compress
        extensions=u16(data,at)
        at+=2
        limit=at+extensions
        if limit>size: return None
        while at+4<=limit:
            kind,n=u16(data,at),u16(data,at+2)
            start=at+4
            end=start+n
            if end>limit: return None
            if kind==0:
                if start+5>end or u16(data,start)+2!=n:return None
                name_type=data[start+2]
                name_len=u16(data,start+3)
                begin=start+5
                finish=begin+name_len
                if name_type!=0 or finish>end:return None
                try: host=data[begin:finish].decode('ascii').lower()
                except UnicodeDecodeError:return None
                return host,begin,finish
            at=end
    except (IndexError,ValueError):
        return None
    return None

def locate_partial_sni(prefix):
    """Recognize a *complete visible* SNI extension before the full TLS record.
    Diagnostic only. Do not label a partial record as a complete ClientHello or
    infer the origin device from the tuple observed at the server.
    """
    data=bytes(prefix)
    if len(data)<9 or data[0]!=22 or data[1]!=3 or data[2]>4 or data[5]!=1:
        return None
    declared=5+u16(data,3)
    if declared<50 or declared>LIMIT:
        return None
    try:
        at=9+2+32
        if at>=len(data):return None
        sid=data[at]
        at+=1+sid
        cipher=u16(data,at)
        at+=2+cipher
        compress=data[at]
        at+=1+compress
        extensions=u16(data,at)
        at+=2
        limit=at+extensions
        if limit>declared:return None
        while at+4<=limit and at+4<=len(data):
            kind,n=u16(data,at),u16(data,at+2)
            start=at+4
            end=start+n
            if end>limit or end>len(data):return None
            if kind==0:
                if start+5>end or u16(data,start)+2!=n:return None
                size=u16(data,start+3)
                endname=start+5+size
                if data[start+2]!=0 or endname>end:return None
                return data[start+5:endname].decode('ascii').lower()
            at=end
    except (IndexError,ValueError,UnicodeDecodeError):
        return None
    return None

class Flow:
    def __init__(self,seq):
        self.start=(seq+1)&0xffffffff
        self.buf=bytearray(LIMIT)
        self.covered=bytearray(LIMIT)
        self.ranges=set()
        # A truncated capture does not reveal the actual TCP segment boundary.
        # Such a flow cannot be classified as SNI-split or unsplit reliably.
        self.segment_boundary_unknown=False
        self.finished=False
    def feed(self,seq,payload,wire_len):
        offset=(seq-self.start)&0xffffffff
        if offset>=LIMIT: return
        n=min(len(payload),LIMIT-offset)
        if n<=0:return
        fresh=False
        overlap=False
        for i in range(n):
            if not self.covered[offset+i]:
                self.buf[offset+i]=payload[i]
                self.covered[offset+i]=1
                fresh=True
            else:
                overlap=True
        # Exclude purely redundant retransmissions: otherwise an initially
        # intact hostname could be falsely reported as split on retry.
        if fresh and wire_len != len(payload):
            self.segment_boundary_unknown=True
        # Partly overlapping retransmissions do not establish which packet
        # boundaries delivered the hostname. Fully redundant retries remain
        # ignored, including short retries of an already complete SNI.
        if fresh and overlap:
            self.segment_boundary_unknown=True
        if fresh and wire_len>0:
            # Never infer a captured segment boundary past captured bytes.
            self.ranges.add((offset,offset+min(wire_len,len(payload))))
    def contiguous_prefix(self):
        n=0
        while n<LIMIT and self.covered[n]:n+=1
        return bytes(self.buf[:n])

    def completed(self):
        if not all(self.covered[:5]):return None
        if self.buf[0]!=22 or self.buf[1]!=3:
            self.finished=True
            return None
        size=5+int.from_bytes(self.buf[3:5],'big')
        if size<50 or size>LIMIT:
            self.finished=True
            return None
        if not all(self.covered[:size]):return None
        self.finished=True
        return bytes(self.buf[:size])

class Analyzer:
    def __init__(self,hosts):
        self.hosts=set(hosts)
        self.flows=OrderedDict()
        self.stats=Counter()
        self.host_counts=Counter()
        self.events=[]
        self.peer_index={}
        self.uncovered_meta=set()
    def tcp(self,ip,port,seq,syn,payload,wire_len=None,timestamp=None):
        key=(ip,port)
        if syn:
            self.flows.pop(key,None)
            if len(self.flows)>=FLOW_LIMIT:
                self.flows.popitem(last=False)
                self.stats['evictions']+=1
            self.flows[key]=Flow(seq)
            self.stats['syn']+=1
            return
        flow=self.flows.get(key)
        if not flow:
            if payload:self.stats['payload_without_syn']+=1
            return
        if flow.finished or not payload:return
        flow.feed(seq,payload,len(payload) if wire_len is None else wire_len)
        record=flow.completed()
        if record is None:return
        info=locate_sni(record)
        if info is None:
            self.stats['no_sni']+=1
            return
        host,begin,end=info
        if host not in self.hosts:
            self.stats['other_sni']+=1
            if host.endswith(('.instagram.com','.facebook.com','.fbcdn.net')):
                if len(self.uncovered_meta)<40:
                    self.uncovered_meta.add(host)
            return
        self.stats['target_clienthello']+=1
        self.host_counts[host]+=1
        if flow.segment_boundary_unknown:
            # The bytes may be reconstructed using retransmissions, but the
            # actual segment boundary was not fully observed. Fail closed.
            self.stats['sni_boundary_indeterminate']+=1
            return
        split=any(begin<b<end for a,b in flow.ranges)
        self.stats['sni_split' if split else 'sni_unsplit']+=1
        if ip not in self.peer_index:
            self.peer_index[ip]=len(self.peer_index)+1
        if len(self.events)<512:
            self.events.append((int(timestamp or 0),self.peer_index[ip],host,split))
    def incomplete_diagnostics(self):
        """Aggregate only; no peer IP, payload, ports or plaintext retained."""
        counts=Counter()
        for flow in self.flows.values():
            if flow.finished:continue
            prefix=flow.contiguous_prefix()
            if not any(flow.covered):
                counts['syn_without_payload']+=1
            elif not prefix:
                counts['prefix_gap_after_syn']+=1
            elif len(prefix)<5:
                counts['tls_header_incomplete']+=1
            elif prefix[0]!=22 or prefix[1]!=3:
                counts['non_tls_first_record']+=1
            elif len(prefix)<6:
                counts['tls_handshake_type_missing']+=1
            elif prefix[5]!=1:
                counts['not_clienthello']+=1
            else:
                counts['clienthello_record_incomplete']+=1
                host=locate_partial_sni(prefix)
                if host in self.hosts:
                    counts['target_sni_visible_in_partial_record']+=1
                elif host:
                    counts['other_sni_visible_in_partial_record']+=1
                elif len(prefix)<50:
                    counts['short_clienthello_prefix']+=1
                else:
                    counts['long_clienthello_without_complete_sni']+=1
        return counts

    def ethernet(self,frame,timestamp=None):
        if len(frame)<14:return
        kind=u16(frame,12)
        at=14
        for _ in range(2):
            if kind not in (0x8100,0x88a8):break
            if len(frame)<at+4:return
            kind=u16(frame,at+2)
            at+=4
        if kind!=0x0800 or len(frame)<at+20:return
        version=frame[at]
        ihl=(version&15)*4
        if version>>4!=4 or ihl<20 or len(frame)<at+ihl or frame[at+9]!=6:
            return
        if u16(frame,at+6)&0x3fff:return
        wire_len=u16(frame,at+2)
        end=min(len(frame),at+wire_len)
        tcp=at+ihl
        if tcp+20>end or u16(frame,tcp+2)!=443:return
        header=(frame[tcp+12]>>4)*4
        if header<20 or tcp+header>end or frame[tcp+13]&4:return
        seq=int.from_bytes(frame[tcp+4:tcp+8],'big')
        payload=frame[tcp+header:end]
        actual=max(0,wire_len-ihl-header)
        self.tcp(bytes(frame[at+12:at+16]),u16(frame,tcp),seq,
                 bool(frame[tcp+13]&2),payload,actual,timestamp)

def read_exact(stream,n):
    chunks=[]
    while n:
        part=stream.read(n)
        if not part:raise EOFError
        chunks.append(part)
        n-=len(part)
    return b''.join(chunks)

def parse_pcap(stream,analyzer,ready=None):
    header=read_exact(stream,24)
    end={'\xd4\xc3\xb2\xa1':'<','\xa1\xb2\xc3\xd4':'>',
         '\x4d\x3c\xb2\xa1':'<','\xa1\xb2\x3c\x4d':'>'}.get(header[:4].decode('latin1'))
    if end is None or struct.unpack(end+'I',header[20:24])[0]!=1:
        raise ValueError('expected classic Ethernet PCAP')
    if ready:ready.set()
    while True:
        # EOF at a record boundary is valid; 1..15 trailing bytes are not.
        first=stream.read(1)
        if not first:break
        rec=first+read_exact(stream,15)
        sec,_fraction,cap,wire=struct.unpack(end+'IIII',rec)
        if cap>PACKET_LIMIT or cap>wire:raise ValueError('unexpected PCAP record')
        analyzer.ethernet(read_exact(stream,cap),timestamp=sec)

def begin(hosts,peer=None):
    import ipaddress
    capture_filter='ip and tcp and dst host 89.125.90.101 and dst port 443'
    if peer is not None:
        capture_filter+=' and src host '+str(ipaddress.IPv4Address(peer))
    analyzer=Analyzer(hosts)
    process=subprocess.Popen(
        ['tcpdump','-i','eth0','-n','-U','-s','1500','-w','-',
         capture_filter],
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
    ready=threading.Event()
    process._mneby_stop_requested=threading.Event()
    failures=[]
    def consume():
        try:
            parse_pcap(process.stdout,analyzer,ready)
            if not process._mneby_stop_requested.is_set():
                failures.append('UnexpectedCaptureEOF')
        except (EOFError,ValueError,OSError) as exc:
            failures.append(type(exc).__name__)
            ready.set()
    thread=threading.Thread(target=consume,daemon=True)
    thread.start()
    if not ready.wait(3) or failures or process.poll() is not None:
        if process.poll() is None:process.kill()
        process.wait(timeout=3)
        thread.join(timeout=3)
        if process.stdout:process.stdout.close()
        raise RuntimeError('SNI PCAP observer failed preflight')
    return process,thread,analyzer,failures

def finish(process,thread,analyzer,failures):
    stopping=getattr(process,'_mneby_stop_requested',None)
    if stopping is not None:stopping.set()
    if process.poll() is None:process.send_signal(signal.SIGINT)
    thread.join(timeout=6)
    if thread.is_alive():
        process.kill()
        thread.join(timeout=4)
    try:
        status=process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        status=process.wait(timeout=3)
        failures.append('CaptureStopTimeout')
    if status not in (0,-signal.SIGINT):
        failures.append('CaptureExit'+str(status))
    if process.stdout:process.stdout.close()
    if thread.is_alive() or failures:
        raise RuntimeError('SNI capture failed: '+','.join(failures))
    return analyzer

def summary(a):
    for name in ('syn','target_clienthello','sni_split','sni_unsplit','sni_boundary_indeterminate','no_sni','other_sni','evictions','payload_without_syn'):
        print('iglite_sni_'+name+'='+str(a.stats[name]),flush=True)
    pending=a.incomplete_diagnostics()
    for kind in ('syn_without_payload','prefix_gap_after_syn','tls_header_incomplete',
                 'tls_handshake_type_missing','non_tls_first_record','not_clienthello',
                 'clienthello_record_incomplete','short_clienthello_prefix',
                 'long_clienthello_without_complete_sni',
                 'target_sni_visible_in_partial_record','other_sni_visible_in_partial_record'):
        print('iglite_sni_partial_'+kind+'='+str(pending[kind]),flush=True)
    for host in sorted(a.hosts):
        print('iglite_sni_host='+host+'|hello='+str(a.host_counts[host]),flush=True)
    print('iglite_sni_source_groups='+str(len(a.peer_index)),flush=True)
    for sec,source_index,hostname,is_split in a.events:
        print('iglite_sni_event=utc_epoch:'+str(sec)
              +'|source_group:'+str(source_index)
              +'|host:'+hostname+'|split:'+str(is_split).lower(),flush=True)
    for hostname in sorted(a.uncovered_meta)[:40]:
        print('iglite_sni_uncovered_meta_hostname='+hostname,flush=True)
    print('iglite_sni_android_identified=false',flush=True)
    print('iglite_sni_pcap_written_to_disk=false',flush=True)

