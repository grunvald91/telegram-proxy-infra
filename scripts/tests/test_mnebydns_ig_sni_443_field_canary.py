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

def wire(src,dst,sport,dport,flags,payload=b""):
    ip=bytearray(20)
    ip[0]=0x45
    struct.pack_into("!H",ip,2,40+len(payload))
    ip[9]=6
    ip[12:16]=ipaddress.IPv4Address(src).packed
    ip[16:20]=ipaddress.IPv4Address(dst).packed
    tcp=bytearray(20+len(payload))
    struct.pack_into("!HH",tcp,0,sport,dport)
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

    def test_server_metadata_observer_counts_only_selected_peer_and_port(self):
        obs=canary.OnePeerPacketCounts(PEER)
        RU=canary.RU
        obs.observe(wire(PEER,RU,55011,443,0x02))
        obs.observe(wire(RU,PEER,443,55011,0x12))
        obs.observe(wire(RU,PEER,443,55011,0x18,b"hidden encrypted server data"))
        obs.observe(wire(PEER,RU,55011,443,0x18,b"1234"))
        obs.observe(wire(PEER,RU,55011,443,0x18,b"second data"))
        obs.observe(wire(PEER,RU,55012,443,0x18,b"long ClientHello"))
        obs.observe(wire("203.0.113.99",RU,55013,443,0x02))
        obs.observe(wire(PEER,RU,55011,80,0x18,b"ignored HTTP"))
        self.assertEqual((obs.inbound_syn,obs.outbound_synack,obs.inbound_payload,
                          obs.inbound_first4,obs.inbound_first_other),
                         (1,1,3,1,1))
        output=io.StringIO()
        with redirect_stdout(output):obs.output()
        self.assertNotIn(PEER,output.getvalue())
        self.assertNotIn("55011",output.getvalue())
        self.assertNotIn("second data",output.getvalue())
        self.assertIn("ig443_phone_first_data_4bytes=1",output.getvalue())
        self.assertIn("ig443_phone_server_data_packets=1",output.getvalue())
        self.assertNotIn("hidden encrypted server data",output.getvalue())

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
