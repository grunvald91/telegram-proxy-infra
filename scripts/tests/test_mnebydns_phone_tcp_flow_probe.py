#!/usr/bin/env python3
"""Offline unit tests of phone participation, single-5-tuple selection and timer."""
from pathlib import Path
import importlib.util
import socket
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"mnebydns_phone_tcp_flow_probe.py"
spec=importlib.util.spec_from_file_location("mneby_phone",FILE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def frame(src, dst, sport, dport, flags, payload=b""):
    # Pure synthetic Ethernet/IPv4/TCP for parser; no external network.
    s=socket.inet_aton(src);d=socket.inet_aton(dst)
    ip=b"\x45\x00"+struct.pack("!H",40+len(payload))+b"\x00"*5+b"\x06"+b"\x00"*2+s+d
    tcp=struct.pack("!HH",sport,dport)+b"\x00"*8+bytes((0x50,flags))+b"\x00"*6
    return b"\x00"*12+b"\x08\x00"+ip+tcp+payload

class PhoneFlowTests(unittest.TestCase):
    PEER="8.8.4.4"
    RU="188.120.254.223"
    NONCE="f0e1d2c3b4a59687"
    def parse(self, src=None, dst=None, sport=51413,dport=443,flags=0x02,payload=b""):
        return mod.packet(frame(src or self.PEER,dst or self.RU,sport,dport,flags,payload),
                          socket.inet_aton(self.PEER))

    def test_challenge_from_approved_ip_only(self):
        payload=("GET /mneby-"+self.NONCE+" HTTP/1.1\r\nHost: 188.120.254.223\r\n\r\n").encode()
        self.assertTrue(mod.match_challenge(self.parse(dport=80,flags=0x18,payload=payload),self.NONCE))
        self.assertFalse(mod.match_challenge(self.parse(dport=443,flags=0x18,payload=payload),self.NONCE))
        self.assertFalse(mod.match_challenge(self.parse(src="1.1.1.1",dport=80,flags=0x18,payload=payload),self.NONCE))
        self.assertFalse(mod.match_challenge(self.parse(dport=80,flags=0x18,payload=payload),self.NONCE[:-1]+"0"))
        self.assertFalse(mod.match_challenge(self.parse(dport=80,flags=0x18,payload=b"GET /other HTTP/1.1\r\n"),self.NONCE))

    def test_pick_exact_peer_syn_and_ignore_unrelated_tcp(self):
        self.assertEqual(mod.pick_syn(self.parse()),51413)
        self.assertIsNone(mod.pick_syn(self.parse(src="1.1.1.1")))
        self.assertIsNone(mod.pick_syn(self.parse(dport=80)))
        self.assertIsNone(mod.pick_syn(self.parse(flags=0x12)))
        self.assertIsNone(mod.pick_syn(self.parse(flags=0x18,payload=b"hello")))
        self.assertIsNone(mod.pick_syn(self.parse(src=self.RU,dst=self.PEER,sport=443,dport=51413,flags=0x12)))

    def test_one_five_tuple_only(self):
        rule=mod.nft_rule(self.PEER,51413,"MNEBY_PHONE_TCP_12345678")
        self.assertIn("ip saddr 188.120.254.223 ip daddr 8.8.4.4",rule)
        self.assertIn("tcp sport 443 tcp dport 51413",rule)
        self.assertIn("ct reply packets 1-20",rule)
        self.assertIn('oifname "ens3"',rule)
        self.assertIn('comment "MNEBY_PHONE_TCP_12345678"',rule)
        self.assertNotIn("delete table",rule)
        with self.assertRaises(ValueError):
            mod.nft_rule(self.PEER,0,"MNEBY_PHONE_TCP_X")

    def test_no_global_table_reset_or_background_server_restart(self):
        code=FILE.read_text()
        self.assertIn("systemd-run",code)
        self.assertIn("on-active=",code)
        self.assertIn('sh(["nft", "--check", "-f", "-"]',code)
        self.assertIn('sh(["nft", "-f", "-"]',code)
        for unsafe in ("delete table", "flush ruleset", '["systemctl", "restart"', "ufw disable"):
            self.assertNotIn(unsafe,code)

    def test_watchdog_is_self_contained_and_handle_only(self):
        with tempfile.TemporaryDirectory() as folder:
            helper=Path(folder)/"rollback.py"
            mod.watchdog(helper,"MNEBY_PHONE_TCP_202611101122")
            content=helper.read_text()
            compile(content,str(helper),"exec")
            self.assertIn("MNEBY_PHONE_TCP_202611101122",content)
            self.assertIn("delete",content)
            self.assertIn("handle",content)
            self.assertNotIn("delete table",content)
            self.assertNotIn("systemctl restart",content)
            self.assertTrue(helper.stat().st_mode & 0o100)

    def test_packet_parser_rejects_truncated_or_non_ip(self):
        self.assertIsNone(mod.packet(b"short",socket.inet_aton(self.PEER)))
        raw=frame(self.PEER,self.RU,51413,443,0x02)
        self.assertIsNone(mod.packet(raw[:30],socket.inet_aton(self.PEER)))
        self.assertIsNone(mod.packet(raw[:12]+b"\x86\xdd"+raw[14:],socket.inet_aton(self.PEER)))

if __name__=="__main__":
    unittest.main()
