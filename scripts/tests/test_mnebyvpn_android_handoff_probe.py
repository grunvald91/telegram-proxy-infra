"""Android transition diagnostics unit tests; never touch an Android device."""
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "mnebyvpn_android_handoff_probe.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("android_handoff", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class AndroidHandoffTests(unittest.TestCase):
    def test_healthy(self):
        self.assertEqual(m.classification({"ok": True}, {"ok": True}), "healthy_observed")

    def test_private_dot_only(self):
        self.assertEqual(m.classification({"ok": True}, {"ok": False}), "private_dot_path_problem")

    def test_android_dns_path_only(self):
        self.assertEqual(m.classification({"ok": False}, {"ok": True}), "system_resolver_problem")

    def test_both_failed(self):
        self.assertEqual(m.classification({"ok": False}, {"ok": False}), "system_dns_and_dot_failed")

    def test_missing_profile_is_unverified(self):
        self.assertEqual(m.classification({"ok": True}, {"ok": None}), "personal_dot_not_tested")

    def test_hostname_only_expected_domain(self):
        with patch.dict("os.environ", {"MNEBYVPN_PRIVATE_DNS_HOST": "abc123def456.dns.mnebyvpn.site"}):
            self.assertEqual(m.private_dns_name(), "abc123def456.dns.mnebyvpn.site")
        with patch.dict("os.environ", {"MNEBYVPN_PRIVATE_DNS_HOST": "attacker.example.org"}):
            self.assertIsNone(m.private_dns_name())

    def test_wifi_hint_does_not_report_identifiers(self):
        with patch.object(m, "command", return_value='{"ssid":"private-home","bssid":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.5","supplicant_state":"COMPLETED"}'):
            self.assertIs(m.wifi_hint(), True)

    def test_hostname_not_printed_in_sample(self):
        source = SCRIPT.read_text(encoding="utf8")
        self.assertNotIn("print(host)", source)
        self.assertIn("vpn_enabled_verified", source)
        self.assertNotIn("systemctl restart", source)


if __name__ == "__main__":
    unittest.main()
