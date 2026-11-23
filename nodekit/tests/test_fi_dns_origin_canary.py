"""Offline invariants for temporary FI regional CoreDNS DoT canary."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_origin_canary as canary


class TestFiDnsOrigin(unittest.TestCase):
    def test_fi_only_and_local_port(self):
        self.assertEqual(canary.PORT, 8853)
        self.assertEqual(canary.NODE, "fi-test-01")
        self.assertEqual(len(set(canary.HOSTS)), 2)
        self.assertTrue(all(x.endswith(".fi.dns.mnebyvpn.site")
                            for x in canary.HOSTS))
        self.assertFalse(any(x.startswith("*") for x in canary.HOSTS))

    def test_require_staged_corefile_and_zero_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fi-test-01"
            (root / "dns-proxy").mkdir(parents=True)
            (root / "tls").mkdir()
            core = root / "dns-proxy/Corefile"
            core.write_text("tls://.:8853 {\n  bind 127.0.0.1\n")
            core.chmod(0o600)
            fixtures = {
                root / "manifest.json": {
                    "node_id": "fi-test-01",
                    "advertise_host": "fi.mnebyvpn.site",
                    "state": "active",
                },
                root / "dns-proxy/manifest.json": {
                    "node_id": "fi-test-01", "state": "staged",
                    "route_count": 0, "personal_dns_enabled": False,
                    "activation_enabled": False,
                    "config_sha256": {"Corefile": "f"*64},
                },
                root / "components-manifest.json": {
                    "binaries": {"coredns": {"sha256": "a"*64}},
                },
            }
            for name,data in fixtures.items():
                name.write_text(json.dumps(data))
                name.chmod(0o600)
            # This is intentionally an untrusted fixture: the validator must
            # reject a modified Corefile even if metadata claims staged.
            with patch.object(canary, "ROOT", root), \
                 patch.object(canary, "require_file", side_effect=lambda p, **kw: p.read_bytes()), \
                 patch.object(canary.os, "geteuid", return_value=0), \
                 patch.object(canary, "COREDNS", core):
                with self.assertRaises(canary.FiDnsOriginError):
                    canary.prepare()

    def test_ephemeral_private_corefile_adds_only_reserved_local_answer(self):
        with tempfile.TemporaryDirectory() as temp:
            original = Path(temp) / "source"
            original.write_text(
                "tls://.:8853 {\n  bind 127.0.0.1\n"
                "  forward . tls://1.1.1.1 tls://1.0.0.1 {\n"
                "    tls_servername cloudflare-dns.com\n  }\n}\n")
            generated = canary.local_test_corefile(original, Path(temp))
            content = generated.read_text()
            self.assertIn(r"match ^fi-dns-canary\.invalid\.$", content)
            self.assertIn('answer "{{ .Name }} 5 IN A 192.0.2.1"', content)
            self.assertIn("tls://.:8853", content)
            self.assertEqual(content.count("  forward . "), 1)
            self.assertNotIn("listen 0.0.0.0", content)
            self.assertEqual(original.read_text().count("template IN A"), 0)
            self.assertEqual(generated.stat().st_mode & 0o777, 0o600)

    def test_question_is_standard_framed_dns_a(self):
        wire = canary.query_bytes(0x1234)
        self.assertEqual(wire[:2], b"\x12\x34")
        self.assertEqual(wire[4:6], b"\0\1")
        self.assertTrue(wire.endswith(b"\x00\x01\x00\x01"))


if __name__ == "__main__":
    unittest.main()
