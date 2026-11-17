import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import hostname_migrate as m


class TestCanonicalCountryHostname(unittest.TestCase):
    def setUp(self):
        self.original = {
            "schema_version": 1,
            "node_id": "fi-test-01",
            "state": "testing",
            "roles": ["dns", "vpn", "sni-proxy", "tunnel"],
            "advertise_host": m.OLD_HOST,
            "listeners": {
                "dot_tcp": 853, "vpn_tcp": 2053,
                "sni_tcp": 443, "tunnel_udp": 51820,
            },
            "registration_enabled": False,
            "activation_enabled": False,
        }
        self.original["spec_sha256"] = hashlib.sha256(
            m.canonical(m.rebuild_spec(self.original, m.OLD_HOST)).encode()
        ).hexdigest()
        self.vpn = {
            "node_id": "fi-test-01", "state": "staged",
            "advertise_host": m.OLD_HOST,
            "activation_enabled": False, "vpn_users_enabled": False,
        }
        self.corefile = "tls://.:8853 {\n  bind 127.0.0.1\n}\n"
        self.nginx = (
            "stream {\n"
            "  map $ssl_preread_server_name $route {\n"
            f"    {m.OLD_HOST} 127.0.0.1:8853;\n"
            "  }\n}\n"
        )
        self.dns = {
            "node_id": "fi-test-01",
            "state": "staged", "route_count": 0,
            "activation_enabled": False,
            "personal_dns_enabled": False,
            "open_proxy_enabled": False,
            "config_sha256": {
                "Corefile": hashlib.sha256(self.corefile.encode()).hexdigest(),
                "nginx.conf": hashlib.sha256(self.nginx.encode()).hexdigest(),
            },
        }

    def test_rewrites_both_manifests_and_dns_sni_without_keys(self):
        result = m.plan(self.original, self.vpn, self.dns,
                        self.nginx, self.corefile)
        self.assertEqual(result["manifest.json"]["advertise_host"], m.NEW_HOST)
        self.assertEqual(result["vpn/vpn-stage-manifest.json"]["advertise_host"],
                         m.NEW_HOST)
        self.assertIn(m.NEW_HOST + " 127.0.0.1:8853;",
                      result["dns-proxy/nginx.conf"])
        self.assertNotIn(m.OLD_HOST, result["dns-proxy/nginx.conf"])
        self.assertEqual(result["manifest.json"]["spec_sha256"], hashlib.sha256(
            m.canonical(m.rebuild_spec(result["manifest.json"], m.NEW_HOST)).encode()
        ).hexdigest())
        self.assertEqual(result["dns-proxy/manifest.json"]["config_sha256"]["Corefile"],
                         self.dns["config_sha256"]["Corefile"])
        self.assertFalse(result["manifest.json"]["activation_enabled"])

    def test_fails_if_identity_or_services_were_published(self):
        for invalid in [
            dict(self.original, state="enabled"),
            dict(self.original, registration_enabled=True),
            dict(self.original, activation_enabled=True),
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(m.RenameError):
                m.plan(invalid, self.vpn, self.dns, self.nginx, self.corefile)
        for bad_dns in [
            dict(self.dns, personal_dns_enabled=True),
            dict(self.dns, route_count=1),
            dict(self.dns, open_proxy_enabled=True),
        ]:
            with self.subTest(bad_dns=bad_dns), self.assertRaises(m.RenameError):
                m.plan(self.original, self.vpn, bad_dns, self.nginx, self.corefile)

    def test_fails_if_existing_files_have_config_drift(self):
        with self.assertRaises(m.RenameError):
            m.plan(self.original, self.vpn, self.dns, "stream {}", self.corefile)
        with self.assertRaises(m.RenameError):
            m.plan(self.original, self.vpn, self.dns, self.nginx, "changed")
        altered = copy.deepcopy(self.original)
        altered["spec_sha256"] = "0"*64
        with self.assertRaises(m.RenameError):
            m.plan(altered, self.vpn, self.dns, self.nginx, self.corefile)

    def test_checks_expected_public_ip(self):
        fake = lambda *_args, **_kwargs: [
            (None,None,None,None,("217.11.167.91",0))
        ]
        self.assertEqual(m.validate_dns(m.NEW_HOST, m.EXPECTED_IP, resolver=fake),
                         ["217.11.167.91"])
        wrong = lambda *_args, **_kwargs: [
            (None,None,None,None,("188.120.254.223",0))
        ]
        with self.assertRaises(m.RenameError):
            m.validate_dns(m.NEW_HOST, m.EXPECTED_IP, resolver=wrong)
        with self.assertRaises(m.RenameError):
            m.validate_dns("fi-test.mnebyvpn.site", m.EXPECTED_IP, resolver=fake)
        with self.assertRaises(m.RenameError):
            m.validate_dns(m.NEW_HOST, "188.120.254.223", resolver=fake)


if __name__ == "__main__":
    unittest.main()
