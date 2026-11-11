#!/usr/bin/env python3
"""Hostile/non-hostile route-collision tests with no server access."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "owner_renderer", BASE / "mnebydns-owner-domain-render-20261110.py"
)
assert spec is not None and spec.loader is not None
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)
TARGET = "www.python.org"
DNS = """tls://.:853 {
    template IN A gemini.google.com {
        match ^gemini[.]google[.]com[.]$
        answer "{{ .Name }} 20 IN A 89.125.90.101"
        fallthrough
    }
    cache 30
}
"""
NGINX = """stream {
map $ssl_preread_server_name $direct_mtproxy_backend {
    default 127.0.0.1:9443;
    gemini.google.com 127.0.0.1:15443;
}
server { proxy_pass $direct_mtproxy_backend; }
}
"""


class OwnerDomainRouteSafety(TestCase):
    def test_unrelated_host_is_additive_and_exact_roundtrip(self):
        a = render.core_add(DNS, TARGET)
        b = render.nginx_add(NGINX, TARGET, "93.184.215.14")
        self.assertEqual(render.core_remove(a, TARGET), DNS)
        self.assertEqual(render.nginx_remove(b, TARGET), NGINX)

    def test_redundant_dot_cache_block_keeps_owner_exact_roundtrip(self):
        upgraded = DNS.replace(
            "    cache 30\n",
            "    cache 30 {\n        servfail 0\n    }\n"
            "    reload 5s 1s\n"
        )
        result = render.core_add(upgraded, TARGET)
        self.assertEqual(render.core_remove(result, TARGET), upgraded)
        self.assertIn("servfail 0", result)
        self.assertIn("reload 5s 1s", result)

    def test_native_core_anchored_regex_is_not_overridden(self):
        core = DNS.replace("cache 30", """template IN A . {
        match ^www[.]python[.]org[.]$
        answer "{{ .Name }} 20 IN A 89.125.90.101"
        fallthrough
    }
    cache 30""")
        with self.assertRaisesRegex(ValueError, "already covers"):
            render.core_add(core, TARGET)

    def test_native_core_parent_zone_covers_hostname(self):
        core = DNS.replace("cache 30", """template IN AAAA python.org {
        rcode NOERROR
    }
    cache 30""")
        with self.assertRaisesRegex(ValueError, "already owns"):
            render.core_add(core, TARGET)

    def test_broad_regex_in_core_is_not_overridden(self):
        core = DNS.replace("cache 30", """template IN A . {
        match ^.*[.]python[.]org[.]$
        answer "{{ .Name }} 20 IN A 89.125.90.101"
        fallthrough
    }
    cache 30""")
        with self.assertRaisesRegex(ValueError, "already covers"):
            render.core_add(core, TARGET)

    def test_core_import_is_rejected_without_expansion(self):
        with self.assertRaisesRegex(ValueError, "Unexpanded CoreDNS imports"):
            render.core_add(DNS.replace("cache 30", "import private/*.conf\n    cache 30"), TARGET)

    def test_nginx_exact_route_is_rejected(self):
        n = NGINX.replace("    default", "    www.python.org 1.2.3.4:443;\n    default")
        with self.assertRaisesRegex(ValueError, "exact SNI"):
            render.nginx_add(n, TARGET, "93.184.215.14")

    def test_nginx_hostnames_wildcard_suffix_is_rejected(self):
        n = NGINX.replace("    default", "    hostnames;\n    *.python.org 1.2.3.4:443;\n    default")
        with self.assertRaisesRegex(ValueError, "wildcard SNI"):
            render.nginx_add(n, TARGET, "93.184.215.14")

    def test_nginx_hostnames_compact_wildcard_is_rejected(self):
        n = NGINX.replace("    default", "    hostnames;\n    .python.org 1.2.3.4:443;\n    default")
        with self.assertRaisesRegex(ValueError, "wildcard SNI"):
            render.nginx_add(n, TARGET, "93.184.215.14")

    def test_nginx_matching_regex_is_rejected(self):
        n = NGINX.replace("    default", r"    ~^www[.]python[.]org$ 1.2.3.4:443;" + "\n    default")
        with self.assertRaisesRegex(ValueError, "regex SNI"):
            render.nginx_add(n, TARGET, "93.184.215.14")

    def test_nginx_matching_case_insensitive_regex_is_rejected(self):
        n = NGINX.replace("    default", "    ~*^WWW[.]PYTHON[.]ORG$ 1.2.3.4:443;\n    default")
        with self.assertRaisesRegex(ValueError, "regex SNI"):
            render.nginx_add(n, TARGET, "93.184.215.14")

    def test_nginx_unexpanded_include_is_rejected(self):
        n = NGINX.replace("    default", "    include /etc/nginx/conf.d/*.map;\n    default")
        with self.assertRaisesRegex(ValueError, "includes unknown"):
            render.nginx_add(n, TARGET, "93.184.215.14")

    def test_nginx_nonmatching_regex_keeps_unrelated_hosts(self):
        n = NGINX.replace("    default", "    ~^only[.]other[.]net$ 1.2.3.4:443;\n    default")
        self.assertEqual(render.nginx_remove(render.nginx_add(n, TARGET, "93.184.215.14"), TARGET), n)

    def test_rejects_self_reference_and_private_upstream(self):
        for ip in ("89.125.90.101", "188.120.254.223", "127.0.0.1", "10.0.0.1"):
            with self.assertRaises(ValueError, msg=ip):
                render.nginx_add(NGINX, TARGET, ip)


if __name__ == "__main__":
    main()
