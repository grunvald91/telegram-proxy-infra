import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_signed_canary as m

class TestSignedCanarySafety(unittest.TestCase):
    def test_only_FI_and_one_disposable_entitlement(self):
        self.assertEqual(m.NODE,"fi-test-01")
        self.assertEqual(m.HOST,"fi.mnebyvpn.site")
        self.assertEqual(m.UID,"00000000-0000-4000-8000-000000000001")
        self.assertEqual(m.TIMER,"nodekit-fi-awg-signed-guard")

    def test_disabled_publishing_is_a_precondition(self):
        node=pathlib.Path("/tmp/fi-test-01")
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"node_ready",return_value=node),\
             patch.object(m,"validate",return_value={}),\
             patch.object(m,"safe_manifest",return_value={
                 "advertise_host":m.HOST,
                 "activation_enabled":False,
                 "registration_enabled":False,
             }),\
             patch.object(m,"active_unit",return_value=True):
            with self.assertRaises(m.CanaryError):
                m.approved_node()

    def test_no_customer_keys_generated_on_node(self):
        import inspect
        s=inspect.getsource(m.prepare)
        self.assertIn("public=stat_file",s)
        self.assertIn("systemd-run",s)
        self.assertIn("O_EXCL",s)
        self.assertNotIn("genpkey",s)
        self.assertNotIn("privateKey",s)

if __name__=="__main__":
    unittest.main()
