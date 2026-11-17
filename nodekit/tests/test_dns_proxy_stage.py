import importlib.util
import ipaddress
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import dns_proxy_stage as m

BASE = {
    "schema_version": 1,
    "node_id": "fi-test-01",
    "external_ipv4": "217.11.167.91",
    "dns_host": "fi-test.mnebyvpn.site",
    "routes": [
        {"domain": "www.youtube.com", "upstream_ipv4": "142.250.73.206"},
        {"domain": "youtubei.googleapis.com", "upstream_ipv4": "142.250.73.202"},
    ],
}


class TestDnsProxy(unittest.TestCase):
    def test_output_is_closed_by_default(self):
        policy = m.validate_policy(BASE, "fi-test-01")
        nginx = m.make_nginx_conf(policy)
        core = m.make_corefile(policy, Path("/var/lib/nodekit/fi-test-01"))
        self.assertIn("default 127.0.0.1:9;", nginx)
        self.assertIn("ssl_preread on;", nginx)
        self.assertIn("youtubei.googleapis.com 142.250.73.202:443;", nginx)
        self.assertIn("fi-test.mnebyvpn.site 127.0.0.1:8853;", nginx)
        self.assertIn("tls://.:8853", core)
        self.assertIn("bind 127.0.0.1", core)
        self.assertIn("template IN A .", core)
        self.assertIn("template IN AAAA .", core)
        self.assertIn("217.11.167.91", core)
        self.assertIn("fallthrough", core)
        self.assertNotIn("listen 0.0.0.0:53", core)
        self.assertNotIn("proxy_pass $ssl_preread_server_name", nginx)
        self.assertNotIn("proxy_pass $host", nginx)

    def test_no_routes_still_denies_every_destination(self):
        policy = m.validate_policy(dict(BASE, routes=[]), "fi-test-01")
        conf = m.make_nginx_conf(policy)
        self.assertEqual(conf.count("default 127.0.0.1:9;"), 2)
        self.assertEqual(policy["routes"], [])

    def test_rejects_private_upstreams_and_host_injection(self):
        failures = [
            [{"domain": "bad;evil.test", "upstream_ipv4": "1.1.1.1"}],
            [{"domain": "localhost", "upstream_ipv4": "1.1.1.1"}],
            [{"domain": "google.com", "upstream_ipv4": "127.0.0.1"}],
            [{"domain": "google.com", "upstream_ipv4": "192.168.1.1"}],
            [{"domain": "google.com", "upstream_ipv4": "217.11.167.91"}],
            [
                {"domain": "google.com", "upstream_ipv4": "1.1.1.1"},
                {"domain": "google.com", "upstream_ipv4": "8.8.8.8"},
            ],
        ]
        for routes in failures:
            with self.subTest(routes=routes), self.assertRaises(m.PolicyError):
                m.validate_policy(dict(BASE, routes=routes), "fi-test-01")

    def test_fails_cross_node_policy(self):
        with self.assertRaises(m.PolicyError):
            m.validate_policy(BASE, "other-node")

    def test_fails_any_extra_policy_field(self):
        with self.assertRaises(m.PolicyError):
            m.validate_policy(dict(BASE, extra="x"), "fi-test-01")


if __name__ == "__main__":
    unittest.main()
