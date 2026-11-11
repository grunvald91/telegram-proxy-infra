#!/usr/bin/env python3
"""Negative/positive exact-RU two-hop candidate tests (no network or VPS)."""
import importlib.util
from pathlib import Path
import unittest

SRC = Path(__file__).resolve().parents[1] / "mnebydns_iglite_ru_twohop_preview.py"
spec = importlib.util.spec_from_file_location("ru_twohop", SRC)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

CORE = (
    "tls://.:853 {\n"
    "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
    "    cache 30\n"
    "}\n"
)
RU = (
    "stream {\n"
    "map $ssl_preread_server_name $direct_mtproxy_backend {\n"
    "  default 10.66.77.1:443;\n"
    "  gemini.google.com 10.66.77.1:443;\n"
    "}\n"
    "server { listen 443; ssl_preread on; proxy_pass $direct_mtproxy_backend; }\n"
    "}\n"
)
DE = (
    "stream {\n"
    "map $ssl_preread_server_name $direct_mtproxy_backend {\n"
    "  default 127.0.0.1:9443;\n"
    "}\n"
    "server { listen 443; ssl_preread on; proxy_pass $direct_mtproxy_backend; }\n"
    "}\n"
)
ORIGIN = "157.240.0.160"


class TwoHopSafety(unittest.TestCase):
    def test_exact_route_is_ru_then_wg_then_verified_meta(self):
        c, n = p.plan(CORE, RU, DE, ORIGIN)
        self.assertIn('answer "{{ .Name }} 20 IN A 188.120.254.223"', c)
        self.assertNotIn('answer "{{ .Name }} 20 IN A 89.125.90.101"', c)
        self.assertEqual(c.count('match ^iglite-z[.]instagram[.]com[.]$'), 5)
        self.assertIn('iglite-z.instagram.com 157.240.0.160:443;', n)
        self.assertIn('default 127.0.0.1:9443;', n)
        self.assertEqual(p.m.core_remove(c, p.HOST), CORE)
        self.assertEqual(p.m.nginx_remove(n, p.HOST), DE)
        self.assertNotIn('*.instagram.com', c+n)
        self.assertNotIn('*.facebook.com', c+n)

    def test_unchanged_ru_requires_existing_private_wg_passthrough(self):
        for bad in [
            RU.replace("10.66.77.1:443", "89.125.90.101:443"),
            RU.replace("default 10.66.77.1:443", "default 127.0.0.1:9443"),
            RU.replace("default 10.66.77.1:443", "default 0.0.0.0:443"),
            RU.replace("proxy_pass $direct_mtproxy_backend;", "proxy_pass 127.0.0.1:9443;"),
            RU.replace("map $ssl_preread_server_name $direct_mtproxy_backend", "map $ssl_preread_server_name $unknown"),
            RU.replace("  default 10.66.77.1:443;", "  default 10.66.77.1:443;\n  iglite-z.instagram.com 9.9.9.9:443;"),
        ]:
            with self.subTest(src=bad[:110]), self.assertRaises(ValueError):
                p.plan(CORE, bad, DE, ORIGIN)

    def test_dns_routing_collision_and_de_route_conflict_fail_closed(self):
        c, n = p.plan(CORE, RU, DE, ORIGIN)
        for core, nginx in [(c, DE), (CORE, n)]:
            with self.subTest(dns=core is c), self.assertRaises(ValueError):
                p.plan(core, RU, nginx, ORIGIN)

    def test_rejects_unsafe_meta_origin(self):
        for address in ("127.0.0.1", "10.66.77.1",
                        "89.125.90.101", "188.120.254.223",
                        "::1", "not-ip"):
            with self.subTest(ip=address), self.assertRaises(ValueError):
                p.plan(CORE, RU, DE, address)

    def test_other_existing_dns_route_is_byte_preserved(self):
        c, n = p.plan(CORE, RU, DE, "57.144.244.32")
        self.assertIn("gemini.google.com", c)
        self.assertEqual(p.m.core_remove(c, p.HOST), CORE)
        self.assertEqual(p.m.nginx_remove(n, p.HOST), DE)

if __name__ == "__main__":
    unittest.main()
