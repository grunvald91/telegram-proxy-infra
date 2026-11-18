"""Contract regression: FI first-contact no longer waits for manual host pin."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/fi-enrollment-trust-preflight-readonly.yml"


class FiAutomaticTrustContract(unittest.TestCase):
    def test_initial_host_pin_is_saved_on_ru188_before_fi_password(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("nodekit/fleet_host_trust.py", text)
        self.assertIn("root@188.120.254.223", text)
        self.assertIn("StrictHostKeyChecking=yes", text)
        self.assertNotIn("StrictHostKeyChecking=accept-new", text)
        self.assertNotIn('fi_pinned_ssh_access=missing', text)
        self.assertLess(text.index('nodekit/fleet_host_trust.py > "$known"'),
                        text.index('export SSHPASS="$FI_PASSWORD"'))
        self.assertIn("FI node identity public key unavailable", text)
        self.assertIn("Pinned FI Nodekit identity mismatch", text)
        self.assertIn("FI Nodekit manifest identity mismatch", text)
        self.assertIn("FI testing node was unexpectedly activated", text)
        self.assertIn("Required FI identity file unsafe", text)
        self.assertIn("Existing FI controller public key is unsafe", text)
        self.assertIn("FI Nodekit identity directory unsafe", text)

    def test_no_production_service_mutation_or_secret_export(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("systemctl start mnebyvpn-fi-enrollment", text)
        self.assertNotIn("systemctl start mnebyvpn-awg-delivery", text)
        self.assertNotIn("StrictHostKeyChecking=no", text)
        self.assertNotIn("print('FI_PASSWORD", text)
        self.assertIn("fi_clients_published=false", text)


if __name__ == "__main__":
    unittest.main()
