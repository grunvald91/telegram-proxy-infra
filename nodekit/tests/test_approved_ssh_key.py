"""Approved host-key parser and fleet workflow fail-closed regressions."""
from pathlib import Path
import base64
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import approved_ssh_key as keys
import fleet_host_trust as trust

REPO = ROOT.parent
FLEET = REPO / ".github/workflows/nodekit-fleet-bootstrap.yml"
FI = REPO / ".github/workflows/fi-enrollment-trust-preflight-readonly.yml"
IP = "217.11.167.91"
KEY = base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" +
    struct.pack(">I", 32) + b"\x42" * 32
).decode()


class ApprovedKeyContract(unittest.TestCase):
    def test_empty_is_automatic_first_contact(self):
        self.assertIsNone(keys.expected_key_from_known_hosts("", IP))

    def test_explicit_public_key_parsed_and_checked(self):
        self.assertEqual(keys.expected_key_from_known_hosts(
            f"# reviewed\n{IP} ssh-ed25519 {KEY} reviewed-node\n", IP), KEY)
        self.assertEqual(keys.expected_key_from_known_hosts(
            f"fi.mnebyvpn.site,{IP} ssh-ed25519 {KEY}", IP), KEY)

    def test_invalid_approved_records_are_not_silently_ignored(self):
        for record in (
            f"1.1.1.1 ssh-ed25519 {KEY}",
            f"{IP} ssh-rsa {KEY}",
            f"{IP} ssh-ed25519 BADBASE64",
            f"{IP} ssh-ed25519 {KEY}\n{IP} ssh-ed25519 {KEY}",
            f"{IP} ssh-ed25519 {KEY} comment extra",
            "# only comments\n",
        ):
            with self.subTest(record=record), self.assertRaises(trust.TrustError):
                keys.expected_key_from_known_hosts(record, IP)


class FleetWorkflowContract(unittest.TestCase):
    def test_empty_inventory_batch_does_not_launch_matrix(self):
        content = FLEET.read_text(encoding="utf-8")
        self.assertIn('print("has_nodes="+("true" if planned else "false")', content)
        self.assertIn("needs.discover.outputs.has_nodes == 'true'", content)

    def test_approved_ssh_key_checks_precede_first_contact_pin(self):
        for path in (FLEET, FI):
            content = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                self.assertIn("nodekit/approved_ssh_key.py", content)
                self.assertIn("--expected-key-b64", content)
                self.assertLess(content.index("approved_ssh_key.py"),
                                content.index("nodekit/fleet_host_trust.py >"))
                self.assertNotIn("StrictHostKeyChecking=accept-new", content)

    def test_architecture_guard_precedes_remote_bundle_transfer(self):
        content = FLEET.read_text(encoding="utf-8")
        self.assertIn('remote_arch="$(remote_ssh \'uname -m\')"', content)
        self.assertIn('"$remote_arch" == x86_64', content)
        self.assertLess(content.index('remote_arch="$(remote_ssh'),
                        content.index('remote_dir=$(remote_ssh'))


if __name__ == "__main__":
    unittest.main()
