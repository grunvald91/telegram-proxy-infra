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
            with patch.object(audit, "ROOT", root), \
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

    def test_certificate_reports_two_distinct_regional_hosts(self):
        self.assertNotEqual(audit.REGIONAL_PROBES[0],
                            audit.REGIONAL_PROBES[1])
        self.assertTrue(all(n.endswith(".fi.dns.mnebyvpn.site")
                            for n in audit.REGIONAL_PROBES))


if __name__ == "__main__":
    unittest.main()
