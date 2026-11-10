#!/usr/bin/env python3
"""Offline exact Instagram Lite route preview and roundtrip regression tests."""
import importlib.util
import re
from pathlib import Path
import unittest

FILE=Path(__file__).resolve().parents[1]/"mnebydns_iglite_route_render_20261111.py"
spec=importlib.util.spec_from_file_location("lite_route",FILE)
lite=importlib.util.module_from_spec(spec)
spec.loader.exec_module(lite)
CORE=("tls://.:853 {\n"
      "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
      "    cache 30\n"
      "}\n")
NGINX=("stream {\n"
       "map $ssl_preread_server_name $direct_mtproxy_backend {\n"
       "  default 127.0.0.1:9443;\n"
       "}\nserver { proxy_pass $direct_mtproxy_backend; }\n"
       "}\n")

ORIGIN="157.240.0.160"  # Observed DE TLS-verified address, offline fixture only

class LiteRouteSafety(unittest.TestCase):
    def test_single_host_and_proven_origin(self):
        self.assertEqual(lite.HOST,"iglite-z.instagram.com")
        self.assertEqual(lite.EDGE,"89.125.90.101")
        core,nginx=lite.render(CORE,NGINX,ORIGIN)
        self.assertEqual(core.count("match ^"+re.escape(lite.HOST).replace(r"\.", "[.]")+r"[.]$"),5)
        self.assertEqual(nginx.count("iglite-z.instagram.com 157.240.0.160:443;"),1)
        self.assertNotIn("*.instagram.com",core+nginx)
        self.assertNotIn("*.facebook.com",core+nginx)
        self.assertEqual(lite.m.core_remove(core,lite.HOST),CORE)
        self.assertEqual(lite.m.nginx_remove(nginx,lite.HOST),NGINX)
        self.assertIn("  default 127.0.0.1:9443;",nginx)

    def test_fails_closed_on_existing_hostname(self):
        core,nginx=lite.render(CORE,NGINX,ORIGIN)
        for x,y in ((core,NGINX),(CORE,nginx)):
            with self.assertRaises(ValueError):
                lite.render(x,y,ORIGIN)

    def test_rejects_private_edge_ru_and_unexpected_origin(self):
        for bad in ("127.0.0.1","89.125.90.101","188.120.254.223",
                    "10.0.0.1","2001:db8::1","not-an-ip"):
            with self.subTest(ip=bad),self.assertRaises(ValueError):
                lite.render(CORE,NGINX,bad)

    def test_pinned_origin_is_explicit_no_implicit_default(self):
        with self.assertRaises(TypeError):
            lite.render(CORE,NGINX)
        core,nginx=lite.render(CORE,NGINX,"57.144.244.32")
        self.assertEqual(lite.m.core_remove(core,lite.HOST),CORE)
        self.assertEqual(lite.m.nginx_remove(nginx,lite.HOST),NGINX)
        self.assertIn("iglite-z.instagram.com 57.144.244.32:443;",nginx)

    def test_existing_unrelated_domain_stays_untouched(self):
        old=NGINX.replace("  default ","  unrelated.example.org 127.0.0.1:9445;\n  default ")
        _,changed=lite.render(CORE,old,ORIGIN)
        self.assertEqual(lite.m.nginx_remove(changed,lite.HOST),old)

if __name__=="__main__":
    unittest.main()
