import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_egress as m

class TestAwgEgress(unittest.TestCase):
    def test_egress_requires_watchdog_and_fails_closed_on_subscriber_acl(self):
        unit=m.unit_source()
        self.assertIn("Requires=mnebyvpn-nodekit-awg-watchdog@%i.service",unit)
        self.assertIn("BindsTo=mnebyvpn-nodekit-awg-watchdog@%i.service",unit)
        self.assertIn("After=mnebyvpn-nodekit-awg-watchdog@%i.service",unit)
        self.assertIn("ExecStopPost=-/usr/bin/python3",unit)
        self.assertNotIn("iptables -P",unit)
        self.assertNotIn("systemctl enable",unit)

    def test_firewall_rules_only_approved_awg_network(self):
        rules=m.firewall()
        self.assertEqual(len(rules),4)
        self.assertEqual(rules[0][0:2],("filter","INPUT"))
        self.assertEqual(rules[3][0:2],("nat","POSTROUTING"))
        self.assertIn("10.73.91.0/24",rules[3][2])
        self.assertIn("MASQUERADE",rules[3][2])
        self.assertIn("51821",rules[0][2])
        for table,chain,args in rules:
            self.assertIn(m.COMMENT,args)
            self.assertNotIn("0.0.0.0/0",args)
        self.assertEqual(m.IFACE,"eth0")
        self.assertEqual(m.HOST,"fi.mnebyvpn.site")

    def test_up_rejected_without_active_controller_watchdog(self):
        with patch.object(m,"active_unit",return_value=False):
            with self.assertRaises(m.EgressError):
                m.up()

    def test_malformed_state_rejected_not_replaced(self):
        with tempfile.TemporaryDirectory() as t:
            path=pathlib.Path(t)/"state"
            path.write_text(json.dumps({"unexpected":"content"}))
            path.chmod(0o600)
            with patch.object(m,"STATE",path):
                with self.assertRaises(m.EgressError):
                    m.state()
                self.assertTrue(path.exists())

    def test_egress_network_state_restoration_config(self):
        with tempfile.TemporaryDirectory() as t:
            state=pathlib.Path(t)/"state"
            state.write_text(json.dumps({
                "schema_version":1,"node_id":m.NODE,"previous_forward":"0",
            }))
            state.chmod(0o600)
            with patch.object(m,"STATE",state):
                self.assertEqual(m.state()["previous_forward"],"0")


if __name__=="__main__":
    unittest.main()
