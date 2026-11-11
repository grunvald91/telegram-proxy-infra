#!/usr/bin/env python3
"""Synthetic binary TCP/PCAP tests; never touch host nft, servers or network."""
from io import BytesIO
from pathlib import Path
import sys
import struct
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from mnebydns_iglite_sni_observer import Analyzer, Flow, locate_sni, parse_pcap

HOST='iglite-z.instagram.com'

def tls_hello(host=HOST):
    name=host.encode('ascii')
    entry=b'\0'+struct.pack('!H',len(name))+name
    ext_body=struct.pack('!H',len(entry))+entry
    extension=b'\0\0'+struct.pack('!H',len(ext_body))+ext_body
    body=(b'\x03\x03'+b'Z'*32+b'\0'+b'\0\x02'+b'\x13\x01'
          +b'\x01\0'+struct.pack('!H',len(extension))+extension)
    handshake=b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x03'+struct.pack('!H',len(handshake))+handshake

def packet(seq,flags,contents=b'',sport=42424):
    tcp=struct.pack('!HHIIHHHH',sport,443,seq,0,(5<<12)|flags,4096,0,0)
    ip=(b'\x45\0'+struct.pack('!H',20+len(tcp)+len(contents))
        +b'\0\0\0\0\x40\x06\0\0'+b'\xcb\x00\x71\x02'
        +b'\x59\x7d\x5a\x65')
    return b'\0'*12+b'\x08\0'+ip+tcp+contents

def make_pcap(records):
    hdr=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,1500,1)
    for p in records:
        hdr+=struct.pack('<IIII',1,1,len(p),len(p))+p
    return BytesIO(hdr)

class ClientHelloBoundaryTests(unittest.TestCase):
    def test_real_sni_offsets(self):
        data=tls_hello()
        value=locate_sni(data)
        self.assertEqual(value[0],HOST)
        self.assertEqual(data[value[1]:value[2]],HOST.encode())
    def test_one_tcp_segment_unsplit(self):
        a=Analyzer([HOST]);ip=b'\xcb\0\x71\x02';p=45601
        a.tcp(ip,p,100,True,b'')
        a.tcp(ip,p,101,False,tls_hello())
        self.assertEqual(a.stats['sni_unsplit'],1)
    def test_split_exactly_inside_sni_out_of_order(self):
        h=tls_hello();i=locate_sni(h)[1]+7
        a=Analyzer([HOST]);ip=b'\xcb\0\x71\x02';p=45601
        a.tcp(ip,p,200,True,b'')
        a.tcp(ip,p,201+i,False,h[i:])
        a.tcp(ip,p,201,False,h[:i])
        a.tcp(ip,p,201,False,h[:i])
        self.assertEqual(a.stats['sni_split'],1)
        self.assertEqual(a.stats['target_clienthello'],1)
    def test_tls_record_split_not_sni_split(self):
        h=tls_hello();a=Analyzer([HOST]);ip=b'\xcb\0\x71\x02';p=45601
        a.tcp(ip,p,100,True,b'')
        a.tcp(ip,p,101,False,h[:10])
        a.tcp(ip,p,111,False,h[10:])
        self.assertEqual(a.stats['sni_unsplit'],1)
    def test_binary_pcap_split(self):
        h=tls_hello();i=locate_sni(h)[1]+5
        raw=make_pcap([packet(800,2),packet(801+i,24,h[i:]),packet(801,24,h[:i])])
        a=Analyzer([HOST])
        parse_pcap(raw,a)
        self.assertEqual(a.stats['sni_split'],1)
    def test_binary_pcap_unsplit(self):
        h=tls_hello()
        a=Analyzer([HOST]);parse_pcap(make_pcap([packet(800,2),packet(801,24,h)]),a)
        self.assertEqual(a.stats['sni_unsplit'],1)
    def test_other_domain_not_counted(self):
        h=tls_hello('example.org')
        a=Analyzer([HOST]);parse_pcap(make_pcap([packet(800,2),packet(801,24,h)]),a)
        self.assertEqual(a.stats['other_sni'],1)
        self.assertEqual(a.stats['target_clienthello'],0)
    def test_sni_event_has_timestamp_and_anonymized_source_group(self):
        data=tls_hello()
        a=Analyzer([HOST])
        peer=b'\xcb\0\x71\x02'
        a.tcp(peer,45454,500,True,b'',timestamp=1794380000)
        a.tcp(peer,45454,501,False,data,timestamp=1794380001)
        self.assertEqual(a.events,[(1794380001,1,HOST,False)])
        self.assertEqual(len(a.peer_index),1)

    def test_extra_meta_sni_name_reported_as_uncovered(self):
        other='gateway.instagram.com'
        a=Analyzer([HOST])
        peer=b'\xcb\0\x71\x02'
        a.tcp(peer,45454,500,True,b'')
        a.tcp(peer,45454,501,False,tls_hello(other))
        self.assertEqual(a.uncovered_meta,{other})
        self.assertEqual(a.stats['other_sni'],1)

    def test_no_raw_ips_or_payload_prints(self):
        import inspect
        from mnebydns_iglite_sni_observer import summary
        s=inspect.getsource(summary)
        self.assertIn('iglite_sni_android_identified=false',s)
        self.assertIn('iglite_sni_pcap_written_to_disk=false',s)
        self.assertNotIn('print(ip',s)
        self.assertNotIn('print(payload',s)

if __name__=='__main__': unittest.main()
