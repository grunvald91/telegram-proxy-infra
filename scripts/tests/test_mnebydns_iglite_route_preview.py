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

class LiteRouteSafety(unittest.TestCase):
    def test_single_host_and_proven_origin(self):
        self.assertEqual(lite.HOST,"iglite-z.instagram.com")
        self.assertEqual(lite.EDGE,"89.125.90.101")
        self.assertEqual(lite.META_ORIGIN,"57.144.244.32")
        core,nginx=lite.render(CORE,NGINX)
        self.assertEqual(core.count("match ^"+re.escape(lite.HOST).replace(r"\.", "[.]")+r"[.]$"),5)
        self.assertEqual(nginx.count("iglite-z.instagram.com 57.144.244.32:443;"),1)
        self.assertNotIn("*.instagram.com",core+nginx)
        self.assertNotIn("*.facebook.com",core+nginx)
        self.assertEqual(lite.m.core_remove(core,lite.HOST),CORE)
        self.assertEqual(lite.m.nginx_remove(nginx,lite.HOST),NGINX)
        self.assertIn("  default 127.0.0.1:9443;",nginx)

    def test_fails_closed_on_existing_hostname(self):
        core,nginx=lite.render(CORE,NGINX)
        for x,y in ((core,NGINX),(CORE,nginx)):
            with self.assertRaises(ValueError):
                lite.render(x,y)

    def test_existing_unrelated_domain_stays_untouched(self):
        old=NGINX.replace("  default ","  unrelated.example.org 127.0.0.1:9445;\n  default ")
        _,changed=lite.render(CORE,old)
        self.assertEqual(lite.m.nginx_remove(changed,lite.HOST),old)

if __name__=="__main__":
    unittest.main()
