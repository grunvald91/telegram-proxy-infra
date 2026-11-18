import json
import stat
from types import SimpleNamespace
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
        with patch.object(m,"lock",return_value=3),\
             patch.object(m,"unlock",return_value=None),\
             patch.object(m,"active_unit",return_value=False):
            with self.assertRaises(m.EgressError):
                m.up()

    def test_malformed_state_rejected_not_replaced(self):
        with tempfile.TemporaryDirectory() as t:
            path=pathlib.Path(t)/"state"
            path.write_text(json.dumps({"unexpected":"content"}))
            path.chmod(0o600)
            stub=SimpleNamespace(
                is_symlink=lambda:False,exists=lambda:True,
                stat=lambda:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,
                                            st_size=len(path.read_bytes())),
                read_text=path.read_text,
            )
            with patch.object(m,"STATE",stub):
                with self.assertRaises(m.EgressError):
                    m.state()
                self.assertTrue(path.exists())

    def test_corrupt_state_removes_duplicate_rules_before_failing_closed(self):
        from unittest.mock import patch
        # Every rule exists twice. A single delete per rule is insufficient.
        live={tuple([table,chain,*args]):2 for table,chain,args in m.firewall()}
        def fake_ipt(table,operation,chain,args,check=True):
            key=tuple([table,chain,*(args[1:] if operation=="-I" else args)])
            if operation=="-C":
                return type("Result",(),{"returncode":0 if live.get(key,0)>0 else 1})()
            if operation=="-D":
                live[key]-=1
                return type("Result",(),{"returncode":0})()
            raise AssertionError(operation)
        with patch.object(m,"state",side_effect=m.EgressError("corrupt")),\
             patch.object(m,"ipt",side_effect=fake_ipt):
            with self.assertRaisesRegex(m.EgressError,"Corrupt state"):
                m._down()
        self.assertTrue(all(count==0 for count in live.values()))

    def test_orphan_rules_are_removed_even_without_state_file(self):
        from unittest.mock import patch
        live={tuple([table,chain,*args]):1 for table,chain,args in m.firewall()}
        def fake_ipt(table,operation,chain,args,check=True):
            key=tuple([table,chain,*args])
            if operation=="-C":
                return type("Result",(),{"returncode":0 if live[key] else 1})()
            if operation=="-D":
                live[key]=0
                return type("Result",(),{"returncode":0})()
            raise AssertionError(operation)
        with patch.object(m,"state",return_value=None),\
             patch.object(m,"ipt",side_effect=fake_ipt):
            result=m._down()
        self.assertEqual(result["network_enabled"],False)
        self.assertTrue(all(count==0 for count in live.values()))

    def test_egress_network_state_restoration_config(self):
        with tempfile.TemporaryDirectory() as t:
            state=pathlib.Path(t)/"state"
            state.write_text(json.dumps({
                "schema_version":1,"node_id":m.NODE,"previous_forward":"0",
            }))
            state.chmod(0o600)
            stub=SimpleNamespace(
                is_symlink=lambda:False,exists=lambda:True,
                stat=lambda:SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,
                                            st_size=len(state.read_bytes())),
                read_text=state.read_text,
            )
            with patch.object(m,"STATE",stub):
                self.assertEqual(m.state()["previous_forward"],"0")


if __name__=="__main__":
    unittest.main()
