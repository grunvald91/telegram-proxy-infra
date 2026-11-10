#!/usr/bin/env python3
"""Offline firewall-rule boundaries and independent cleanup tests."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
spec=importlib.util.spec_from_file_location("ig443_canary",BASE/"mnebydns_ig_sni_443_field_canary.py")
canary=importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)

PEER="185.137.178.123"
RUN="42887901234"
TAG=canary.tag_for(RUN)

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
        self.assertIn("ip saddr 188.120.254.223 ip daddr 185.137.178.123",nft)
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
