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

    def test_missing_personal_profile_plus_failed_resolver_is_unverified(self):
        self.assertEqual(m.classification({"ok": False}, {"ok": None}),
                         "system_resolver_failed_dot_unverified")

    def test_unverified_dot_does_not_recover_open_incident(self):
        events, open_incident, streak = m.next_transition(
            True, 2, "personal_dot_not_tested")
        self.assertEqual(events, [])
        self.assertTrue(open_incident)
        self.assertEqual(streak, 0)

    def test_simultaneous_wifi_and_incident_start_are_preserved(self):
        events, open_incident, streak = m.next_transition(
            False, 1, "private_dot_path_problem", wifi_changed=True)
        self.assertEqual(events, ["wifi_hint_changed", "incident_started"])
        self.assertTrue(open_incident)
        self.assertEqual(streak, 2)

    def test_recovery_requires_both_paths_observed_healthy(self):
        events, open_incident, streak = m.next_transition(
            True, 3, "healthy_observed", wifi_changed=True)
        self.assertEqual(events, ["wifi_hint_changed", "incident_recovered"])
        self.assertFalse(open_incident)
        self.assertEqual(streak, 0)

    def test_hostname_only_expected_domain(self):
        with patch.dict("os.environ", {"MNEBYVPN_PRIVATE_DNS_HOST": "abc123def456.dns.mnebyvpn.site"}):
            self.assertEqual(m.private_dns_name(), "abc123def456.dns.mnebyvpn.site")
        with patch.dict("os.environ", {"MNEBYVPN_PRIVATE_DNS_HOST": "attacker.example.org"}):
            self.assertIsNone(m.private_dns_name())

    def test_wifi_hint_does_not_report_identifiers(self):
        with patch.object(m, "command", return_value='{"ssid":"private-home","bssid":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.5","supplicant_state":"COMPLETED"}'):
            self.assertIs(m.wifi_hint(), True)

    def test_switch_between_two_connected_wifi_networks(self):
        one = '{"ssid":"WiFi-A","bssid":"aa:bb:cc:dd:ee:01","supplicant_state":"COMPLETED"}'
        two = '{"ssid":"WiFi-B","bssid":"aa:bb:cc:dd:ee:02","supplicant_state":"COMPLETED"}'
        with patch.object(m, "command", return_value=one):
            wifi1, token1 = m.wifi_hint(b"ephemeral-key")
        with patch.object(m, "command", return_value=two):
            wifi2, token2 = m.wifi_hint(b"ephemeral-key")
        self.assertTrue(wifi1)
        self.assertTrue(wifi2)
        self.assertNotEqual(token1, token2)
        self.assertEqual(len(token1), 32)
        self.assertNotIn(b"WiFi-A", token1)

    def test_no_location_permission_returns_unknown(self):
        with patch.object(m, "command", return_value=None):
            self.assertEqual(m.wifi_hint(b"ephemeral-key"), (None, None))

    def test_hostname_not_printed_in_sample(self):
        source = SCRIPT.read_text(encoding="utf8")
        self.assertNotIn("print(host)", source)
        self.assertIn("vpn_enabled_verified", source)
        self.assertNotIn("systemctl restart", source)

    def test_personal_dot_ingress_targets_ru188(self):
        self.assertEqual(m.IP, "188.120.254.223")
        seen = []
        class FakeTls:
            def __init__(self): self._buf = b""
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, _): pass
            def sendall(self, data):
                txid = int.from_bytes(data[2:4], "big")
                q = data[14:]
                pkt = (int.to_bytes(txid, 2, "big") + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" +
                       q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd7\x0e")
                self._buf = len(pkt).to_bytes(2, "big") + pkt
            def recv(self, n):
                out, self._buf = self._buf[:n], self._buf[n:]
                return out
        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, _): pass
        class FakeCtx:
            def wrap_socket(self, _sock, server_hostname):
                seen.append(("sni", server_hostname))
                return FakeTls()
        def connect(ep, timeout=3.5):
            seen.append(("connect", ep))
            return FakeSock()
        with patch.object(m.socket, "create_connection", side_effect=connect), \
             patch.object(m.ssl, "create_default_context", return_value=FakeCtx()):
            res = m.actual_personal_dot("abc123def456.dns.mnebyvpn.site")
        self.assertTrue(res["ok"])
        self.assertEqual(seen, [("connect", ("188.120.254.223", 853)), ("sni", "abc123def456.dns.mnebyvpn.site")])


if __name__ == "__main__":
    unittest.main()
