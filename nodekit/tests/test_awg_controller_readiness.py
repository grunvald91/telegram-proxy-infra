import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_controller_readiness as m

PUBLIC=bytes.fromhex("302a300506032b6570032100")+bytes(range(32))
PUBLIC_SHA=hashlib.sha256(PUBLIC).hexdigest()
CONTROLLER_SHA='c'*64

class TestControllerReadiness(unittest.TestCase):
    def test_absent_controller_public_key_is_not_an_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=pathlib.Path(tmp)
            pinned,sha=m.optional_controller_spki(node)
            self.assertFalse(pinned)
            self.assertIsNone(sha)

    def test_symlinked_trust_anchor_never_counts_as_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=pathlib.Path(tmp)
            (node/"controller-access.spki").symlink_to("/etc/hosts")
            with self.assertRaises(Exception):
                m.optional_controller_spki(node)

    def test_missing_independent_spki_pin_blocks_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=pathlib.Path(tmp)/"fi-test-01"
            node.mkdir()
            (node/"amneziawg").mkdir()
            with patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m,"awg_validate",return_value={}),\
                 patch.object(m,"safe_manifest",return_value={"advertise_host":m.HOST_REVIEWED}),\
                 patch.object(m,"protected_file",return_value=PUBLIC),\
                 patch.object(m,"optional_controller_spki",return_value=(True,CONTROLLER_SHA)),\
                 patch.object(m,"source_is_installed",return_value=True),\
                 patch.object(m,"active_unit",return_value=False),\
                 patch.object(m,"enabled_unit",return_value=False):
                result=m.inspect(node,m.HOST_REVIEWED,PUBLIC_SHA)
                self.assertFalse(result["controller_public_key_independently_pinned"])
                self.assertFalse(result["control_plane_prerequisites_met"])
                result=m.inspect(node,m.HOST_REVIEWED,PUBLIC_SHA,CONTROLLER_SHA)
                self.assertTrue(result["controller_public_key_independently_pinned"])
                self.assertTrue(result["control_plane_prerequisites_met"])
                self.assertEqual(result["grant_ledger_count"],0)
                with self.assertRaises(m.ReadinessError):
                    m.inspect(node,m.HOST_REVIEWED,PUBLIC_SHA,"b"*64)

    def test_invalid_node_identity_is_hard_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=pathlib.Path(tmp)/"fi-test-01"
            node.mkdir()
            with patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m,"awg_validate",return_value={}),\
                 patch.object(m,"safe_manifest",return_value={"advertise_host":m.HOST_REVIEWED}),\
                 patch.object(m,"protected_file",return_value=PUBLIC):
                with self.assertRaises(m.ReadinessError):
                    m.inspect(node,m.HOST_REVIEWED,"f"*64)
                with self.assertRaises(m.ReadinessError):
                    m.inspect(node,"xx.mnebyvpn.site",PUBLIC_SHA)

if __name__=="__main__":
    unittest.main()
