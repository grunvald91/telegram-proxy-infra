"""No-network fixtures for in-memory ClientHello fingerprint diagnostic."""
import importlib.util
from pathlib import Path
import socket
import struct
import unittest

FILE=Path(__file__).resolve().parents[1]/"de89-google-tls-fingerprint-readonly-20261117.py"
SPEC=importlib.util.spec_from_file_location("tls_prefix_fp",FILE)
MOD=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

def fixture(src,dst,sport,dport,payload,kind=276):
    tcp=struct.pack("!HHIIHHHH",sport,dport,10,10,0x5018,4096,0,0)+payload
    ip_total=20+len(tcp)
    ip=(struct.pack("!BBHHHBBH",0x45,0,ip_total,0,0,64,6,0)
        +socket.inet_aton(src)+socket.inet_aton(dst))
    if kind==276:
        sll=b"\x08\x00"+b"\x00"*18
    elif kind==113:
        sll=b"\x00"*14+b"\x08\x00"
    else:
        sll=b"\x00"*12+b"\x08\x00"
    return sll+ip+tcp

class FingerprintParserTests(unittest.TestCase):
    def test_external_hello_and_pilot_forward_same_prefix(self):
        tls=bytes([22,3,1,0,100,1])+bytes(range(70))
        pub=MOD.parse_frame(fixture("198.51.100.25",MOD.PUBLIC,41233,443,tls),276)
        pilot=MOD.parse_frame(fixture(MOD.LOCAL,MOD.LOCAL,51123,15449,tls),276)
        self.assertEqual(MOD.leg(*pub[:4]),"PUBLIC_CLIENT")
        self.assertEqual(MOD.leg(*pilot[:4]),"PILOT_CLIENT")
        self.assertEqual(MOD.tls_kind(pub[-1]),"CLIENT_HELLO")
        self.assertEqual(pub[-1][:64],pilot[-1][:64])

    def test_server_hello_and_small_server_response(self):
        hello=bytes([22,3,3,0,80,2])+bytes(range(65))
        p=MOD.parse_frame(fixture(MOD.PUBLIC,"198.51.100.25",443,41000,hello),276)
        self.assertEqual(MOD.leg(*p[:4]),"PUBLIC_SERVER")
        self.assertEqual(MOD.tls_kind(p[-1]),"SERVER_HELLO")
        self.assertEqual(p[4],len(hello))

    def test_other_link_types(self):
        hello=bytes([22,3,1,0,90,1])+bytes(range(65))
        for kind in (1,113,276):
            self.assertEqual(MOD.parse_frame(fixture("198.51.100.25",MOD.PUBLIC,41000,443,hello,kind),kind)[-1],hello)

    def test_no_short_record_fingerprints(self):
        self.assertIsNone(MOD.tls_kind(b"\x16\x03\x03\x00\x25\x01"))
        self.assertIsNone(MOD.tls_kind(b"\x17"+b"\x00"*100))
        self.assertIsNone(MOD.parse_frame(b"\0"*13,276))

if __name__=="__main__":
    unittest.main()
