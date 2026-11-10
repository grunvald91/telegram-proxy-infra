#!/usr/bin/env python3
"""Independent packet-byte tests for isolated Android IPv4 HTTPS/443 canary."""
import ipaddress
import struct
import sys
from pathlib import Path
from unittest import TestCase

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
import mnebydns_ig_sni_443_fragment_worker as worker
RU="188.120.254.223"
PEER="9.9.9.9"
OTHER="203.0.113.42"

def packet(*,src=RU,dst=PEER,sport=443,flags=0x12,window=64240,options=b"\x03\x03\x07\x01",payload=b"",frag=0,protocol=6):
    assert len(options)%4==0
    tcp_len=20+len(options)+len(payload)
    ip=bytearray(20)
    struct.pack_into("!BBHHHBBH",ip,0,0x45,0,20+tcp_len,1,frag,64,protocol,0)
    ip[12:16]=ipaddress.IPv4Address(src).packed
    ip[16:20]=ipaddress.IPv4Address(dst).packed
    struct.pack_into("!H",ip,10,worker.checksum(ip))
    tcp=bytearray(20+len(options)+len(payload))
    struct.pack_into("!HHII",tcp,0,sport,59127,123,456)
    tcp[12]=((20+len(options))//4)<<4
    tcp[13]=flags
    struct.pack_into("!H",tcp,14,window)
    tcp[20:20+len(options)]=options
    tcp[20+len(options):]=payload
    pseudo=ip[12:20]+struct.pack("!BBH",0,6,len(tcp))
    struct.pack_into("!H",tcp,16,worker.checksum(pseudo+tcp))
    return bytes(ip+tcp)

class PhoneSniFragmentBytes(TestCase):
    def test_exact_peer_443_synack_window_only(self):
        before=packet()
        after=worker.transform(before,peer=PEER)
        self.assertNotEqual(before,after)
        self.assertEqual(struct.unpack_from("!H",after,34)[0],4)
        self.assertEqual(after[:34],before[:34])
        self.assertEqual(after[38:],before[38:])
        pseudo=after[12:20]+struct.pack("!BBH",0,6,len(after)-20)
        self.assertEqual(worker.checksum(pseudo+after[20:]),0)
        self.assertEqual(worker.checksum(after[:20]),0)

    def test_preserves_ecn_and_tcp_options(self):
        before=packet(flags=0xd2)
        after=worker.transform(before,peer=PEER)
        self.assertNotEqual(before,after)
        self.assertEqual(after[33],before[33])
        self.assertEqual(after[40:],before[40:])

    def test_does_not_change_any_non_matching_packet(self):
        cases=[
            packet(sport=18443),packet(sport=8443),
            packet(src=OTHER),packet(dst=OTHER),
            packet(flags=0x10),packet(flags=0x02),packet(flags=0x11),
            packet(flags=0x18),packet(flags=0x1a),
            packet(payload=b"hello"),packet(frag=1),packet(frag=0x2000),
            packet(protocol=17),packet(window=4),
            packet()[:-1],b"broken",b"",
            packet()[:41],packet(flags=0xd0),
        ]
        for entry in cases:
            with self.subTest(i=repr(entry[:15])):
                self.assertEqual(worker.transform(entry,peer=PEER),entry)

    def test_wrong_peer_never_clamps(self):
        self.assertEqual(worker.transform(packet(),peer="185.137.178.124"),packet())

    def test_client_sni_payload_never_clamped(self):
        src=packet(src=PEER,dst=RU,sport=59127,flags=0x18,payload=b"\x16\x03\x01Instagram")
        self.assertEqual(worker.transform(src,peer=PEER),src)
