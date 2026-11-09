#!/usr/bin/env python3
"""Bounded, read-only MNEBYDNS Meta TCP/UDP stage observer.

Starts tcpdump on a single named interface, reads binary PCAP only in memory,
prints aggregate counts, never writes a capture or records client IPs/SNI.
Source/destination tuples exist only in the process for de-duplication. Intended
for a brief explicitly requested time-limited canary.
"""
from __future__ import annotations
import argparse
import collections
import os
import re
import select
import signal
import struct
import subprocess
import sys
import time

TARGETS = {
    'ru': ('188.120.254.223', (443, 443)),
    'de': ('10.66.77.1', (19443, 19444)),
}
META_SUFFIXES = ('instagram.com', 'cdninstagram.com', 'instagr.am', 'ig.me',
                 'threads.com', 'threads.net', 'facebook.com', 'facebook.net',
                 'fbcdn.net', 'fb.com', 'meta.com', 'meta.ai', 'igsonar.com',
                 'fbsbx.com', 'instagramstatic.com', 'igcdn.com', 'fbcdn.com')
MAX_PCAP_FRAME = 8192
MAX_TCP_STATE = 30000


def read_int(data: bytes, offset: int, fmt: str):
    return struct.unpack_from(fmt, data, offset)[0]


def tls_clienthello_name(payload: bytes):
    """Return (hello, Meta) for a single complete TLS ClientHello record.

    Unknown/fragmented records are *not* counted as confirmed SNI; the Nginx
    sidecar can independently account for fully reconstructed TLS sessions.
    """
    if len(payload) < 9 or payload[:1] != b'\x16' or payload[1] != 3:
        return False, False
    record_size = int.from_bytes(payload[3:5], 'big')
    if record_size < 4 or record_size > 16384 or len(payload) < record_size + 5:
        return False, False
    handshake = payload[5:5 + record_size]
    if handshake[:1] != b'\x01' or len(handshake) < 4:
        return False, False
    need = int.from_bytes(handshake[1:4], 'big')
    if need + 4 > len(handshake) or need < 43:
        return False, False
    body = handshake[4:4 + need]
    try:
        i = 34
        session = body[i]; i += 1 + session
        if i + 2 > len(body): return True, False
        n = int.from_bytes(body[i:i+2], 'big'); i += 2 + n
        if i >= len(body): return True, False
        n = body[i]; i += 1 + n
        if i + 2 > len(body): return True, False
        ext_n = int.from_bytes(body[i:i+2], 'big'); i += 2
        end = i + ext_n
        if end > len(body): return True, False
        while i + 4 <= end:
            typ, n = struct.unpack_from('!HH', body, i); i += 4
            if i + n > end: return True, False
            if typ == 0 and n >= 5:
                ext = body[i:i+n]
                if ext[2] == 0:
                    hostname_len = int.from_bytes(ext[3:5], 'big')
                    host = ext[5:5+hostname_len].decode('ascii', errors='ignore').lower()
                    return True, any(host == z or host.endswith('.' + z) for z in META_SUFFIXES)
            i += n
    except (IndexError, struct.error, ValueError):
        return True, False
    return True, False


def decode_frame(frame: bytes, linktype: int):
    """Yield (ip_version, src, dst, transport, sport, dport, flags, payload)."""
    try:
        if linktype == 1:   # Ethernet / VLAN
            if len(frame) < 14: return None
            eth = int.from_bytes(frame[12:14], 'big')
            p = 14
            while eth in (0x8100, 0x88A8, 0x9100):
                if len(frame) < p + 4: return None
                eth = int.from_bytes(frame[p+2:p+4], 'big')
                p += 4
            if eth not in (0x0800, 0x86dd): return None
        elif linktype == 113:  # Linux cooked SLL1
            if len(frame) < 16: return None
            p = 16
        elif linktype == 276:  # Linux cooked SLL2
            if len(frame) < 20: return None
            p = 20
        elif linktype in (12, 101): # RAW
            p = 0
        else: return None
        if len(frame) < p + 20: return None
        version = frame[p] >> 4
        if version == 4:
            header = (frame[p] & 15) * 4
            if header < 20 or len(frame) < p + header: return None
            if (int.from_bytes(frame[p+6:p+8], 'big') & 0x1fff):return None
            protocol = frame[p+9]
            src, dst = bytes(frame[p+12:p+16]), bytes(frame[p+16:p+20])
            cursor = p + header
        elif version == 6:
            if len(frame) < p + 40:return None
            protocol = frame[p+6]
            src, dst = bytes(frame[p+8:p+24]), bytes(frame[p+24:p+40])
            cursor = p + 40
            if protocol not in (6,17):return None  # IPv6 extension chain not parsed.
        else: return None
        if protocol not in (6,17) or len(frame) < cursor+8:return None
        sport,dport = struct.unpack_from('!HH', frame, cursor)
        if protocol == 6:
            if len(frame) < cursor+20:return None
            head = ((frame[cursor+12] >> 4) * 4)
            if head < 20 or len(frame) < cursor + head:return None
            flags = frame[cursor+13]
            payload = frame[cursor+head:]
        else:
            flags = 0
            payload = frame[cursor+8:]
        return version,src,dst,protocol,sport,dport,flags,payload
    except (struct.error, ValueError):
        return None


class Observer:
    def __init__(self, role):
        self.role = role
        ip,(self.tcp_port,self.udp_port) = TARGETS[role]
        self.ip = bytes(map(int,ip.split('.')))
        self.c = collections.Counter()
        self.sessions = collections.OrderedDict()

    def packet(self, frame, linktype):
        x=decode_frame(frame,linktype)
        if x is None:
            self.c['unparsed']+=1
            return
        version,src,dst,proto,sport,dport,flags,data=x
        if version == 4 and dst==self.ip and (proto,dport) in ((6,self.tcp_port),(17,self.udp_port)):
            direction='in'
        elif version == 4 and src==self.ip and (proto,sport) in ((6,self.tcp_port),(17,self.udp_port)):
            direction='out'
        else:
            # Observer never claims to have monitored a different route/family.
            self.c['other_packets']+=1
            return
        if proto==17:
            self.c['udp_'+direction]+=1
            if len(data)>=5 and data[0]&0xf0==0xc0 and data[1:5]==b'\x00\x00\x00\x01':
                self.c['udp_quic_v1_initial_'+direction]+=1
            elif data and data[0]&0x80:
                self.c['udp_other_long_header_'+direction]+=1
            return
        self.c['tcp_'+direction]+=1
        if flags&0x02 and not flags&0x10:self.c['tcp_syn_'+direction]+=1
        if flags&0x02 and flags&0x10:self.c['tcp_synack_'+direction]+=1
        if flags&0x04:self.c['tcp_reset_'+direction]+=1
        if flags&0x01:self.c['tcp_fin_'+direction]+=1
        if not data:return
        self.c['tcp_payload_packets_'+direction]+=1
        self.c['tcp_payload_bytes_'+direction]+=len(data)
        if direction=='in':
            key=(src,sport,dst,dport)
            if key not in self.sessions:
                if len(self.sessions)>=MAX_TCP_STATE:self.sessions.popitem(last=False)
                self.sessions[key]=False
            if not self.sessions[key]:
                hello,meta=tls_clienthello_name(data)
                if hello:
                    self.sessions[key]=True
                    self.c['tcp_clienthello_'+direction]+=1
                    if meta:self.c['tcp_clienthello_meta_'+direction]+=1
                    else:self.c['tcp_clienthello_other_or_ech_'+direction]+=1

    def report(self, final=False):
        p='meta_stage_'+self.role+'_'+('FINAL' if final else 'WINDOW')+'_'
        keys=('tcp_syn_in','tcp_synack_out','tcp_clienthello_in',
              'tcp_clienthello_meta_in','tcp_clienthello_other_or_ech_in',
              'tcp_payload_packets_in','tcp_payload_packets_out','tcp_payload_bytes_in',
              'tcp_payload_bytes_out','tcp_reset_in','tcp_reset_out',
              'udp_in','udp_out','udp_quic_v1_initial_in',
              'udp_other_long_header_in','unparsed')
        print(' '.join(f'{p}{k}={self.c[k]}' for k in keys),flush=True)


def read_pcap_packet(buf: bytearray, endian, linktype, obs: Observer):
    consumed=0
    while len(buf)-consumed>=16:
        _ts,_usec,caplen,_wirelen=struct.unpack_from(endian+'IIII',buf,consumed)
        if caplen>MAX_PCAP_FRAME:
            raise ValueError('untrusted oversized pcap frame')
        if len(buf)-consumed<16+caplen:break
        obs.packet(bytes(buf[consumed+16:consumed+16+caplen]),linktype)
        consumed+=16+caplen
    if consumed:del buf[:consumed]


def pcap_header(buf: bytearray):
    if len(buf)<24:return None
    magic=bytes(buf[:4])
    if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'):endian='<'
    elif magic in (b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'):endian='>'
    else:raise ValueError('tcpdump did not emit a classic pcap header')
    _major,_minor,_tz,_sig,_snap,linktype=struct.unpack_from(endian+'HHiIII',buf,4)
    del buf[:24]
    if linktype not in (1,12,101,113,276):raise ValueError('unsupported linktype '+str(linktype))
    return endian,linktype


def consume_file(path,role):
    obs=Observer(role)
    buf=bytearray()
    with open(path,'rb') as f:
        header=f.read(24)
        buf.extend(header)
        x=pcap_header(buf)
        assert x is not None
        endian,linktype=x
        for chunk in iter(lambda:f.read(1<<16),b''):
            buf.extend(chunk)
            read_pcap_packet(buf,endian,linktype,obs)
    if buf:raise ValueError('truncated pcap')
    obs.report(final=True)
    return obs


def capture_live(role,interface,seconds):
    target,(tcp,udp)=TARGETS[role]
    bpf=f'host {target} and ((tcp and port {tcp}) or (udp and port {udp}))'
    # No output file. Capture remains inside memory and the pipe only.
    cmd=['tcpdump','-i',interface,'-n','-U','-s','4096','-w','-',bpf]
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          stdin=subprocess.DEVNULL,bufsize=0)
    obs=Observer(role)
    assert proc.stdout is not None
    fd=proc.stdout.fileno()
    buf=bytearray(); head=None
    deadline=time.monotonic()+seconds
    next_report=time.monotonic()+10
    try:
        while time.monotonic()<deadline:
            if proc.poll() is not None:
                raise RuntimeError('tcpdump stopped unexpectedly with exit='+str(proc.returncode))
            ready,_,_=select.select([fd],[],[],min(1.0,max(0,deadline-time.monotonic())))
            if ready:
                chunk=os.read(fd,65536)
                if not chunk:raise RuntimeError('tcpdump pipe closed')
                buf.extend(chunk)
                if head is None:head=pcap_header(buf)
                if head:
                    read_pcap_packet(buf,head[0],head[1],obs)
            if time.monotonic()>=next_report:
                obs.report()
                next_report=time.monotonic()+10
        obs.report(final=True)
        return obs
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        try:proc.wait(timeout=4)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)
        proc.stdout.close()


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--role',required=True,choices=('ru','de'))
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--interface')
    mode.add_argument('--pcap')
    p.add_argument('--seconds',type=int,default=240)
    args=p.parse_args()
    if args.pcap:consume_file(args.pcap,args.role)
    else:
        if args.seconds<5 or args.seconds>1800:raise SystemExit('observer window must be 5..1800 seconds')
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,24}',args.interface):raise SystemExit('invalid interface')
        capture_live(args.role,args.interface,args.seconds)

if __name__=='__main__':main()