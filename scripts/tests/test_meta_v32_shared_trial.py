from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from meta_v15_receive_window import nft_rules,WindowProxy
from meta_v25_source_view import render
from meta_v31_sni_evidence import CaptureEvidence
from meta_v29_two_server_sequence import checked_phone_ip
from test_meta_v23_ru_firsthop_preview import CORE

class SharedTrialTests(unittest.TestCase):
    def test_shared_rules_remain_ru_interface_endpoint_and_socket_scoped(self):
        rules=nft_rules('188.120.254.223','all',interface='ens3')
        self.assertIn('iifname "ens3" ip daddr 188.120.254.223 tcp dport 443',rules)
        self.assertIn('ip saddr 188.120.254.223 tcp sport 18443',rules)
        self.assertNotIn('ip saddr all',rules)
        with self.assertRaises(ValueError):nft_rules('89.125.90.101','all')
    def test_shared_receiver_preserves_non_meta_ru_backend(self):
        proxy=WindowProxy('188.120.254.223','all',backend=('10.66.77.1',443),non_meta_backend=('188.120.254.223',443))
        self.assertIsNone(proxy.peer)
        self.assertEqual(proxy.destination_for('i.instagram.com'),('10.66.77.1',443))
        self.assertEqual(proxy.destination_for('www.youtube.com'),('188.120.254.223',443))
        with self.assertRaises(ValueError):WindowProxy('89.125.90.101','all')
    def test_shared_dns_is_one_reversible_server_without_source_view(self):
        plan=render(corefile=CORE,phone_ip='all',compiled_plugins='view template tls')
        plan.verify_rollback()
        self.assertNotIn('client_ip()',plan.candidate)
        self.assertEqual(plan.candidate.count('tls://.:853'),1)
        self.assertEqual(plan.candidate.count('IN A 188.120.254.223'),11)
    def test_capture_and_controller_accept_explicit_all_scope(self):
        self.assertEqual(checked_phone_ip('all'),'all')
        cap=CaptureEvidence('all',Path('unused.json'))
        self.assertNotIn('src host',cap.command[-1])
        self.assertIn('dst host 188.120.254.223 and dst port 443',cap.command[-1])
if __name__=='__main__':unittest.main()
