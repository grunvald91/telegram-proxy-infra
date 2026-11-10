#!/usr/bin/env python3
"""Offline firewall-rule boundaries and independent cleanup tests."""
import importlib.util
import ipaddress
import io
import struct
from contextlib import redirect_stdout
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
spec=importlib.util.spec_from_file_location("ig443_canary",BASE/"mnebydns_ig_sni_443_field_canary.py")
canary=importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)

PEER="9.9.9.9"
RUN="42887901234"
TAG=canary.tag_for(RUN)

def wire(src,dst,sport,dport,flags,payload=b"",*,seq=1,ack=0,window=64240):
    ip=bytearray(20)
    ip[0]=0x45
    struct.pack_into("!H",ip,2,40+len(payload))
    ip[9]=6
    ip[12:16]=ipaddress.IPv4Address(src).packed
    ip[16:20]=ipaddress.IPv4Address(dst).packed
    tcp=bytearray(20+len(payload))
    struct.pack_into("!HHII",tcp,0,sport,dport,seq,ack)
    struct.pack_into("!H",tcp,14,window)
    tcp[12]=0x50
    tcp[13]=flags
    tcp[20:]=payload
    return b"\0"*12+b"\x08\x00"+bytes(ip+tcp)

class ScopedAndroidCanary(unittest.TestCase):
    def test_peer_and_runid_strict(self):
        self.assertEqual(canary.validate(PEER,RUN),PEER)
        for address in ("127.0.0.1","10.1.2.3","188.120.254.223","::1","not-ip"):
            with self.subTest(address=address),self.assertRaises(ValueError):
                canary.validate(address,RUN)
        for ident in ("1","0"*10,"1;reboot","../../etc",""):
            with self.subTest(run=ident),self.assertRaises(ValueError):
                canary.validate(PEER,ident)

    def test_nft_and_iptables_exact_peer_synack_only(self):
        nft=canary.nft_rule(PEER,TAG)
        self.assertIn("ip saddr 188.120.254.223 ip daddr 9.9.9.9",nft)
        self.assertIn("tcp sport 443",nft)
        self.assertIn("flags & (syn | ack) == (syn | ack)",nft)
        self.assertIn("ct reply packets 1-20 meta mark & 0x40000000 == 0",nft)
        self.assertIn('counter return comment "'+TAG+'"',nft)
        self.assertNotIn("flush",nft.lower())
        args=canary.iptables_rule(PEER,TAG)
        self.assertEqual(args[:4],["-s","188.120.254.223","-d",PEER])
        self.assertIn("--sport",args)
        self.assertEqual(args[args.index("--sport")+1],"443")
        self.assertIn("--queue-bypass",args)
        self.assertEqual(args[args.index("--queue-num")+1],"211")
        self.assertEqual(args[args.index("--comment")+1],TAG)

    def test_timer_outlasts_trial(self):
        self.assertGreater(canary.WATCHDOG_TIME,canary.TEST_TIME)
        self.assertLessEqual(canary.WATCHDOG_TIME,120)

    def test_rollback_only_deletes_exact_tagged_rules(self):
        snapshot=f'''table inet telegram_nfqws {{
 chain post {{
 type filter hook postrouting priority filter; policy accept;
 tcp sport 443 counter queue num 210 bypass # handle 17
 ip daddr {PEER} counter return comment "{TAG}" # handle 47
 }}
}}'''
        calls=[]
        def fake_run(args,**kwargs):
            calls.append(args)
            return type("Result",(),{"returncode":0})()
        with patch.object(canary,"iptables_present",side_effect=[True,False]),\
             patch.object(canary,"chain",side_effect=[snapshot,"chain post {\\n}"]),\
             patch.object(canary,"run",side_effect=fake_run):
            canary.cleanup(PEER,TAG)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0][:6],["iptables","-w","-t","mangle","-D","OUTPUT"])
        self.assertEqual(calls[1],["nft","delete","rule","inet","telegram_nfqws","post","handle","47"])

    def test_ambiguous_cleanup_refuses_broad_delete(self):
        snap=(f'comment "{TAG}" # handle 2\n'+f'comment "{TAG}" # handle 3')
        with patch.object(canary,"iptables_present",return_value=False),\
             patch.object(canary,"chain",return_value=snap):
            with self.assertRaises(RuntimeError):
                canary.cleanup(PEER,TAG)

    def test_correlates_tcp_handshake_window_tls_prefix_and_deduplicates(self):
        obs = canary.OnePeerPacketCounts(PEER)
        ru = canary.RU
        hello4 = b"\x16\x03\x01\x02"
        # Flow 55011: actual SYN/SYNACK(window4)/ACK, then TLS header prefix.
        obs.observe(wire(PEER, ru, 55011, 443, 0x02, seq=100))
        obs.observe(wire(ru, PEER, 443, 55011, 0x12, seq=1000, ack=101, window=4))
        obs.observe(wire(PEER, ru, 55011, 443, 0x10, seq=101, ack=1001))
        obs.observe(wire(ru, PEER, 443, 55011, 0x18,
                         b"encrypted server response", seq=1001, ack=105))
        obs.observe(wire(PEER, ru, 55011, 443, 0x18, hello4, seq=101, ack=1001))
        obs.observe(wire(PEER, ru, 55011, 443, 0x18, hello4, seq=101, ack=1001))
        obs.observe(wire(PEER, ru, 55011, 443, 0x18, b"continuation", seq=105, ack=1001))
        # Uncorrelated data from the same public peer must be excluded.
        obs.observe(wire(PEER, ru, 55012, 443, 0x18, hello4, seq=101))
        obs.observe(wire("203.0.113.99", ru, 55012, 443, 0x02))
        obs.observe(wire(PEER, ru, 55011, 80, 0x18, b"ignored HTTP"))
        # Flow 55013 has full handshake but a NORMAL window. Never count
        # this as proof that the experimental clamp worked.
        obs.observe(wire(PEER, ru, 55013, 443, 0x02, seq=200))
        obs.observe(wire(ru, PEER, 443, 55013, 0x12, seq=3000, ack=201))
        obs.observe(wire(PEER, ru, 55013, 443, 0x10, seq=201, ack=3001))
        obs.observe(wire(PEER, ru, 55013, 443, 0x18,
                         b"\x16\x03\x01\x00\x40", seq=201, ack=3001))
        self.assertEqual((obs.inbound_syn, obs.outbound_synack,
                          obs.outbound_synack_window4, obs.inbound_payload,
                          obs.inbound_first4, obs.inbound_first_other,
                          obs.inbound_first_untrusted, obs.outbound_payload),
                         (2, 2, 1, 3, 1, 0, 1, 1))
        output = io.StringIO()
        with redirect_stdout(output):
            obs.output()
        report = output.getvalue()
        self.assertIn("ig443_phone_segment_measurement_eligible=true", report)
        self.assertIn("ig443_phone_tls_prefix_first_4bytes=1", report)
        self.assertIn("ig443_phone_first_data_untrusted=1", report)
        for private in (PEER, "55011", "continuation", "encrypted server response"):
            self.assertNotIn(private, report)

    def test_no_false_success_from_missing_handshake_or_wrong_ack(self):
        obs = canary.OnePeerPacketCounts(PEER)
        ru = canary.RU
        prefix = b"\x16\x03\x01\x02"
        obs.observe(wire(PEER, ru, 52001, 443, 0x18, prefix, seq=101))
        obs.observe(wire(PEER, ru, 52002, 443, 0x02, seq=100))
        obs.observe(wire(ru, PEER, 443, 52002, 0x12, seq=1000, ack=999, window=4))
        obs.observe(wire(PEER, ru, 52002, 443, 0x10, seq=101, ack=1001))
        obs.observe(wire(PEER, ru, 52002, 443, 0x18, prefix, seq=101, ack=1001))
        self.assertEqual(obs.inbound_first4, 0)
        self.assertEqual(obs.inbound_payload, 0)
        output = io.StringIO()
        with redirect_stdout(output):
            obs.output()
        self.assertIn("ig443_phone_segment_measurement_eligible=false", output.getvalue())

    def test_non_tls_first_segment_is_not_mislabeled_clienthello(self):
        obs = canary.OnePeerPacketCounts(PEER)
        ru = canary.RU
        obs.observe(wire(PEER, ru, 52001, 443, 0x02, seq=100))
        obs.observe(wire(ru, PEER, 443, 52001, 0x12, seq=1000, ack=101, window=4))
        obs.observe(wire(PEER, ru, 52001, 443, 0x10, seq=101, ack=1001))
        obs.observe(wire(PEER, ru, 52001, 443, 0x18, b"1234", seq=101, ack=1001))
        self.assertEqual(obs.inbound_first4, 0)
        self.assertEqual(obs.inbound_first_untrusted, 1)

    def test_fragmented_ip_and_flow_cap_mark_evidence_invalid(self):
        obs = canary.OnePeerPacketCounts(PEER)
        obs.MAX_FLOWS = 1
        first = wire(PEER, canary.RU, 55001, 443, 0x02, seq=100)
        fragmented = bytearray(first)
        struct.pack_into("!H", fragmented, 14 + 6, 0x2000)
        obs.observe(bytes(fragmented))
        self.assertEqual(obs.inbound_syn, 0)
        obs.observe(first)
        obs.observe(wire(PEER, canary.RU, 55002, 443, 0x02, seq=200))
        self.assertTrue(obs.overflow)
        self.assertEqual(obs.inbound_syn, 1)
        output = io.StringIO()
        with redirect_stdout(output):
            obs.output()
        self.assertIn("ig443_phone_observer_overflow=true", output.getvalue())
        self.assertIn("ig443_phone_segment_measurement_eligible=false", output.getvalue())

    def test_rollback_script_stdlib_only_imports(self):
        source=(BASE/"mnebydns_ig_sni_443_field_canary.py").read_text()
        # Imports of kernel worker remain in its own script only, so copied
        # on-server rollback needs no module path or live checkout.
        self.assertNotIn("from mnebydns_nfq_failopen",source)
        self.assertNotIn("import mnebydns_ig_sni_443_fragment_worker",source)
        self.assertNotIn("systemctl stop telegram-nfqws",source)
        self.assertNotIn("nft delete table",source)

if __name__=="__main__":
    unittest.main()
