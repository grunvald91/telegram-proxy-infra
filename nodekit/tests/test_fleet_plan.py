import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fleet_plan as m


class TestFleetInventory(unittest.TestCase):
    def setUp(self):
        self.fi = {
            "schema_version": 1, "country_code": "FI",
            "node_id": "fi-test-01", "advertise_host": "fi.mnebyvpn.site",
            "ssh_ipv4": "217.11.167.91", "role": "combined",
            "services": list(m.SERVICES),
            "listeners": dict(m.LISTENERS), "status": "testing",
            "automatic_bootstrap_allowed": True,
            "subscriber_publication_allowed": False,
            "expected_identity_public_sha256": "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9",
        }

    def check(self, value=None, country="fi"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / (country + ".json")).write_text(
                json.dumps(self.fi if value is None else value))
            return m.inventory(root, country)

    def test_fi_inventory_creates_compatible_immutable_nodekit_spec(self):
        policy, spec = self.check()
        self.assertEqual(spec["node_id"], "fi-test-01")
        self.assertEqual(spec["advertise_host"], "fi.mnebyvpn.site")
        self.assertEqual(policy["ssh_ipv4"], "217.11.167.91")
        self.assertNotIn("ssh_ipv4", spec)
        self.assertNotIn("subscriber_publication_allowed", spec)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "spec.json"
            m.write_spec(target, spec)
            self.assertEqual(json.loads(target.read_text()), spec)
            self.assertEqual(target.stat().st_mode & 0o077, 0)
            with self.assertRaises(m.FleetError):
                m.write_spec(target, spec)

    def test_no_publication_or_unapproved_host(self):
        changes = [
            {"subscriber_publication_allowed": True},
            {"automatic_bootstrap_allowed": False},
            {"advertise_host": "fi-test.mnebyvpn.site"},
            {"advertise_host": "de.mnebyvpn.site"},
            {"ssh_ipv4": "89.125.90.101"},
            {"ssh_ipv4": "188.120.254.223"},
            {"ssh_ipv4": "127.0.0.1"},
            {"ssh_ipv4": "192.168.1.1"},
            {"ssh_ipv4": "217.11.167.91;rm -rf /"},
            {"ssh_ipv4": "217.11.167.091"},
            {"status": "enabled"},
            {"status": "planned"},
            {"country_code": "DE"},
            {"node_id": "fi;shutdown"},
            {"expected_identity_public_sha256": "bad"},
            {"listeners": dict(m.LISTENERS, sni_tcp=8080)},
            {"services": ["vpn"]},
            {"other_field": "extra"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(m.FleetError):
                self.check(dict(self.fi, **change))

    def test_no_remote_plan_lookup_from_untrusted_path(self):
        for country in ("../fi", "Fi", "fi;cmd", "", "fii", "de/../../x"):
            # Never construct a write path from an intentionally hostile name.
            with tempfile.TemporaryDirectory() as temp:
                with self.subTest(country=country), self.assertRaises(m.FleetError):
                    m.inventory(Path(temp), country)

    def test_other_country_is_supported_with_reviewed_record(self):
        row = dict(
            self.fi, country_code="NL", advertise_host="nl.mnebyvpn.site",
            ssh_ipv4="203.0.113.2", node_id="nl-01",
            expected_identity_public_sha256=None,
        )
        # Reserved documentation addresses are NOT routable.
        with self.assertRaises(m.FleetError):
            self.check(row, "nl")


if __name__ == "__main__":
    unittest.main()
