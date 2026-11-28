"""FI Smart DNS read-only inventory unit contract."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_live_inventory as audit


class TestFiDnsInventory(unittest.TestCase):
    def test_defaults_do_not_claim_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fi-test-01"
            root.mkdir()
            (root / "dns-proxy").mkdir()
            (root / "tls").mkdir()
            for directory, name, data in [
                (root, "manifest.json", {"state": "active",
                    "advertise_host": audit.HOST}),
                (root / "dns-proxy", "manifest.json",
                 {"state": "staged", "route_count": 0}),
                (root / "tls", "manifest.json",
                 {"hostname": audit.HOST}),
            ]:
                path = directory / name
                path.write_text(json.dumps(data))
                path.chmod(0o600)
            # The CI fixture is intentionally not root-owned; ownership
            # rejection itself is independently tested below.
            with patch.object(audit, "ROOT", root), \
                 patch.object(audit, "secure_json",
                              side_effect=lambda p: json.loads(p.read_text())
                              if p.is_file() else None), \
                 patch.object(audit.os, "geteuid", return_value=0), \
                 patch.object(audit, "certificate_summary",
                              return_value={"candidates": [],
                                            "regional_wildcard_present": False}), \
                 patch.object(audit, "listening_tcp_ports", return_value=[443]), \
                 patch.object(audit, "systemd_active", return_value=False), \
                 patch.object(audit, "command",
                              return_value=type("Result", (), {"returncode": 1})()):
                result = audit.gather()
            self.assertTrue(result["dns_candidate_stage"])
            self.assertEqual(result["dns_candidate_route_count"], 0)
            self.assertFalse(result["regional_tls"]["regional_wildcard_present"])
            self.assertFalse(result["public_release_authorized"])
            self.assertFalse(result["customer_settings_changed"])

    def test_unsafe_manifest_is_not_treated_as_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "manifest.json"
            file.write_text('{"state":"active"}')
            file.chmod(0o644)
            self.assertIsNone(audit.secure_json(file))
            file.unlink()
            file.symlink_to("/etc/hosts")
            self.assertIsNone(audit.secure_json(file))

    def test_inventory_includes_real_regional_tls_stage(self):
        from fi_regional_cert_stage import DEST
        self.assertIn(DEST / "fullchain.pem", audit.CERT_CANDIDATES)

    def test_inventory_includes_metered_loopback_port(self):
        result = type("Result", (), {
            "returncode": 0,
            "stdout": "LISTEN 0 128 127.0.0.1:18854 0.0.0.0:*\n",
        })()
        with patch.object(audit, "command", return_value=result):
            self.assertEqual(audit.listening_tcp_ports(), [18854])

    def test_certificate_reports_two_distinct_regional_hosts(self):
        self.assertNotEqual(audit.REGIONAL_PROBES[0],
                            audit.REGIONAL_PROBES[1])
        self.assertTrue(all(n.endswith(".fi.dns.mnebyvpn.site")
                            for n in audit.REGIONAL_PROBES))


    def test_country_dns_answer_rejects_wrong_id_and_question(self):
        import struct
        q=audit.fixed_question()
        reply=struct.pack("!HHHHHH",0x4a71,0x8180,1,1,0,0)+q[12:]+bytes([192,12,0,1,0,1,0,0,0,10,0,4,192,0,2,1])
        self.assertTrue(audit.valid_answer(reply,q))
        self.assertFalse(audit.valid_answer(bytes([0])+reply[1:],q))
        self.assertFalse(audit.valid_answer(reply[:13]+b"x"+reply[14:],q))
        self.assertFalse(audit.valid_answer(reply[:len(q)],q))

    def test_country_probe_only_exact_test_names_and_local_ports(self):
        with patch.object(audit.socket,"create_connection") as connect:
            self.assertEqual(audit.country_probe("other.example",8853,b"x"),"invalid_probe")
            self.assertEqual(audit.country_probe(audit.COUNTRY_PROBES[0],853,b"x"),"invalid_probe")
            connect.assert_not_called()

    def test_country_summary_never_probes_inactive_service(self):
        with patch.object(audit,"systemd_active",return_value=False), patch.object(audit,"country_probe") as probe:
            result=audit.country_live_summary()
        self.assertEqual(result["origin"],"not_tested")
        probe.assert_not_called()

    def test_country_summary_refuses_non_loopback_listener(self):
        with patch.object(audit,"systemd_active",return_value=True), patch.object(audit,"command",return_value=type("Result",(),{"returncode":0,"stdout":"LISTEN 0 128 0.0.0.0:8853 0.0.0.0:*"})()), patch.object(audit,"country_probe") as probe:
            result=audit.country_live_summary()
        self.assertEqual(result["origin"],"unexpected_listener")
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
