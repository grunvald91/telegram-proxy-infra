#!/usr/bin/env python3
"""Offline regressions for the Meta-domain foreign GooglePilot renderer."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
RENDER = ROOT / "scripts/mnebydns-meta-foreign-family-render-20261112.py"
spec = importlib.util.spec_from_file_location("meta_foreign", RENDER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

DNS = ("tls://.:853 {\n"
       "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
       "    cache 30\n"
       "    forward . tls://9.9.9.9 {}\n}\n")
NGINX = ("stream {\n"
         " map $ssl_preread_server_name $direct_mtproxy_backend {\n"
         "    default 127.0.0.1:9443;\n"
         "    www.youtube.com 127.0.0.1:15449;\n"
         "    gemini.google.com 127.0.0.1:15443;\n"
         " }\n"
         " server {\n    ssl_preread on;\n"
         "    proxy_pass $direct_mtproxy_backend;\n }\n}\n")
PILOT = ("stream {\n"
         "  resolver 9.9.9.9 ipv6=off valid=30s;\n"
         "  map $ssl_preread_server_name $experimental_origin {\n"
         "    default 127.0.0.1:1;\n"
         "    www.youtube.com www.youtube.com:443;\n"
         "    ~*^(.+\\.)?googlevideo\\.com$ $ssl_preread_server_name:443;\n"
         "  }\n"
         "  server {\n    ssl_preread on;\n"
         "    proxy_pass $experimental_origin;\n  }\n}\n")

class ForeignMetaTests(unittest.TestCase):
    def test_existing_routes_are_preserved(self):
        d, n, p = mod.render(DNS, NGINX, PILOT).values()
        self.assertIn("www.youtube.com 127.0.0.1:15449;", n)
        self.assertIn("gemini.google.com 127.0.0.1:15443;", n)
        self.assertIn("www.youtube.com www.youtube.com:443;", p)
        self.assertIn(r"googlevideo\.com", p)
        self.assertIn("template IN A gemini.google.com", d)
        self.assertIn("forward . tls://9.9.9.9", d)
        self.assertIn("127.0.0.1:15449;", n)

    def test_full_meta_family_and_cdn(self):
        mod.preflight()
        dn, nx = mod.patterns()
        for host in ("i.instagram.com", "graph.instagram.com",
                     "iglite-z.instagram.com", "scontent.xx.fbcdn.net",
                     "scontent-xyz.cdninstagram.com",
                     "accounts.facebook.com", "graph.threads.net",
                     "igcdn-videos-a-0-a.akamaihd.net"):
            self.assertTrue(mod.belongs_to_meta(host), host)
            self.assertIsNotNone(__import__("re").fullmatch(dn,host+"."),host)
            self.assertIsNotNone(__import__("re").fullmatch(nx[2:],host,flags=__import__("re").I),host)
        for host in ("youtube.com","example.com","akamas.us","other.akamaihd.net",
                     "facebook.com.attacker.test","evilfbcdn.net"):
            self.assertFalse(mod.belongs_to_meta(host),host)

    def test_unowned_or_conflicting_maps_fail_closed(self):
        with self.assertRaises(ValueError):
            mod.render_shared_nginx(NGINX.replace("direct_mtproxy_backend",
                                                       "wrong_var"))
        with self.assertRaises(ValueError):
            mod.render_googlepilot(PILOT.replace("ssl_preread on;", ""))
        with self.assertRaises(ValueError):
            mod.render_googlepilot(PILOT.replace("resolver 9.9.9.9 ipv6=off valid=30s;",""))
        with self.assertRaises(ValueError):
            mod.render_coredns(DNS.replace("cache 30","cache 50"))
        with self.assertRaises(ValueError):
            mod.render_coredns(DNS+" # instagram.com exists")
        with self.assertRaises(ValueError):
            mod.render_shared_nginx(NGINX.replace("gemini.google.com","www.instagram.com"))

    def test_no_duplicate_route_install(self):
        configs = mod.render(DNS,NGINX,PILOT)
        with self.assertRaises(ValueError):
            mod.render(configs["Corefile.meta-candidate"],
                       configs["nginx.meta-candidate"],
                       configs["googlepilot.meta-candidate"])

    def test_render_is_offline_and_files_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            d = pathlib.Path(temp)
            a,b,c=[d/x for x in ("dns.original", "shared.original", "pilot.original")]
            for name,body in ((a,DNS),(b,NGINX),(c,PILOT)):
                name.write_text(body)
            out = d/"out"
            out.mkdir()
            result = subprocess.run(
                [sys.executable,str(RENDER),"render","--dns",str(a),
                 "--shared-nginx",str(b),"--googlepilot",str(c),"--out-dir",str(out)],
                text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(a.read_text(),DNS)
            self.assertEqual(b.read_text(),NGINX)
            self.assertEqual(c.read_text(),PILOT)
            self.assertEqual(len(list(out.iterdir())),4)
            self.assertIn("TCP/443 only",result.stdout)
            again = subprocess.run(
                [sys.executable,str(RENDER),"render","--dns",str(a),
                 "--shared-nginx",str(b),"--googlepilot",str(c),"--out-dir",str(out)],
                text=True,capture_output=True)
            self.assertNotEqual(again.returncode,0,"Must not overwrite prior artifacts")

if __name__ == "__main__":
    unittest.main()
