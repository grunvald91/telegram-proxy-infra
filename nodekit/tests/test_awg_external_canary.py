import base64
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_external_canary as m

KEY=base64.b64encode(bytes(range(32))).decode()

class TestPublicAwgCanary(unittest.TestCase):
    def test_source_ipv4_must_be_public_and_canonical(self):
        assert m.source_ip("8.8.8.8") == "8.8.8.8"
        for value in ("127.0.0.1","10.0.0.1","192.168.1.1",
                      "169.254.169.254","::1","8.8.08.8"):
            with self.subTest(ip=value),self.assertRaises(ValueError):
                m.source_ip(value)

    def test_all_rules_are_limited_to_one_client_and_runner_source(self):
        rows=m.firewall("8.8.8.8")
        self.assertEqual(len(rows),4)
        inbound=rows[0]
        self.assertEqual(inbound[0:2],("filter","INPUT"))
        self.assertEqual(inbound[2][inbound[2].index("-s")+1],"8.8.8.8")
        self.assertEqual(inbound[2][inbound[2].index("--dport")+1],"51821")
        self.assertEqual(rows[3][0:2],("nat","POSTROUTING"))
        self.assertIn("10.73.91.2/32",rows[3][2])
        self.assertIn("MASQUERADE",rows[3][2])
        for _,_,terms in rows:
            self.assertIn(m.MARK,terms)
            self.assertNotIn("0.0.0.0/0",terms)

    def test_server_never_uses_customer_keys_in_temporary_test(self):
        self.assertTrue(m.key_ok(KEY))
        self.assertFalse(m.key_ok("wrong"))
        self.assertFalse(m.key_ok("B"*44))
        self.assertEqual(m.NODE,"fi-test-01")
        self.assertEqual(m.HOST,"fi.mnebyvpn.site")

    def test_operator_service_guard_before_any_network_mutation(self):
        with patch.object(m,"node_ready",return_value=pathlib.Path("/tmp/fi-test-01")),\
             patch.object(m,"validate",return_value={}),\
             patch.object(m,"safe_manifest",return_value={
                 "advertise_host":m.HOST,
                 "activation_enabled":False,
                 "registration_enabled":False,
             }),\
             patch.object(m,"active_unit",return_value=True):
            with self.assertRaises(m.CanaryError):
                m.check_node()

if __name__=="__main__":
    unittest.main()
