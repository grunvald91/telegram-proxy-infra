"""Signed FI217 production AWG egress must fail closed before NAT/forward."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import awg_egress as egress


class SignedEgressTests(unittest.TestCase):
    def setUp(self):
        self.node = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
        self.node_manifest = {
            "node_id": egress.NODE, "advertise_host": egress.HOST,
            "state": "active", "activation_enabled": True,
            "registration_enabled": True,
        }
        self.awg = {
            "node_id": egress.NODE, "state": "active",
            "activation_enabled": True, "peers_enabled": True,
            "subscribers_enabled": False,
            "test_address": "10.73.91.1/24", "port": 51821,
        }
        self.proof = {
            "mode": "production", "production_approval": "signed",
            "customer_release": False,
            "approved_binary_identity": "pinned",
            "approved_config_identity": "pinned",
        }

    def test_forged_or_incomplete_production_state_never_passes(self):
        for obj, field, bad in [
            ("node", "activation_enabled", False),
            ("node", "registration_enabled", False),
            ("node", "state", "testing"),
            ("awg", "state", "staged"),
            ("awg", "activation_enabled", False),
            ("awg", "peers_enabled", False),
            ("awg", "subscribers_enabled", True),
            ("proof", "mode", "staged"),
            ("proof", "production_approval", None),
            ("proof", "customer_release", True),
            ("proof", "approved_binary_identity", "unreviewed"),
            ("proof", "approved_config_identity", "unreviewed"),
        ]:
            with self.subTest(obj=obj, field=field):
                manifest, awg, proof = self.node_manifest.copy(), self.awg.copy(), self.proof.copy()
                {"node": manifest, "awg": awg, "proof": proof}[obj][field] = bad
                with self.assertRaises(egress.EgressError):
                    egress.production_mode(manifest, awg, proof)

    def test_exact_signed_production_mode_allowed_without_starting_services(self):
        self.assertEqual(
            egress.production_mode(self.node_manifest, self.awg, self.proof),
            "production",
        )
        node, awg, report = self.node_manifest.copy(), self.awg.copy(), {"mode":"staged"}
        node.update({"state":"testing","activation_enabled":False,"registration_enabled":False})
        awg.update({"state":"staged","peers_enabled":False,"subscribers_enabled":False})
        self.assertEqual(egress.production_mode(node, awg, report),"staged")
        node["activation_enabled"]=True
        with self.assertRaises(egress.EgressError):
            egress.production_mode(node,awg,report)

    def test_real_egress_validator_uses_signed_awg_gate_and_existing_route(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder)
            (binary/"awg").write_bytes(b"pinned by lifecycle gate")
            def manifest(path):
                return self.awg if path.name == "manifest.json" and path.parent.name == "amneziawg" else self.node_manifest
            with patch.object(egress,"validate_awg",return_value=self.proof), \
                 patch.object(egress,"safe_manifest",side_effect=manifest), \
                 patch.object(egress,"AWG_BIN",binary), \
                 patch.object(egress,"call",return_value=SimpleNamespace(stdout=json.dumps([{"dev":"eth0"}]))):
                result=egress.validate(self.node)
                self.assertEqual(result["runtime_mode"],"production")
                self.assertTrue(result["signed_production_approval"])
                forged=dict(self.proof, production_approval="unsigned")
                with patch.object(egress,"validate_awg",return_value=forged):
                    with self.assertRaises(egress.EgressError):
                        egress.validate(self.node)
                with patch.object(egress,"call",return_value=SimpleNamespace(stdout=json.dumps([{"dev":"ens3"}]))):
                    with self.assertRaises(egress.EgressError):
                        egress.validate(self.node)

    def test_entrypoint_still_requires_awg_and_watchdog_and_no_release(self):
        source=(Path(__file__).parents[1]/"awg_egress.py").read_text()
        self.assertIn("node=node_ready(ROOT,NODE,allow_production=True)",source)
        self.assertIn("approved = validate_awg(node)",source)
        self.assertIn("if not active_unit(unit_name(NODE)) or not active_unit(WATCHDOG)",source)
        self.assertIn("BindsTo=mnebyvpn-nodekit-awg-watchdog@%i.service",source)
        self.assertNotIn("vpn_release_flags SET",source)
        self.assertNotIn("systemctl\", \"enable",source)

if __name__ == "__main__":
    unittest.main()
