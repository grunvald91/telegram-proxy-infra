import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import tls_stage as m


class Stub:
    def __init__(self, stdout=b""):
        self.stdout = stdout
        self.returncode = 0


class TestTLSStage(unittest.TestCase):
    def test_acme_http01_command_uses_one_exact_hostname_and_no_arbitrary_shell(self):
        invoked = []
        def fake(cmd, **kwargs):
            invoked.append(cmd)
            return Stub()
        m.issue("fi.mnebyvpn.site", runner=fake)
        self.assertEqual(len(invoked), 1)
        command = invoked[0]
        self.assertEqual(command[:3], ["certbot", "certonly", "--standalone"])
        self.assertEqual(command[command.index("-d") + 1], "fi.mnebyvpn.site")
        self.assertIn("--non-interactive", command)
        self.assertIn("--agree-tos", command)
        self.assertIn("--register-unsafely-without-email", command)
        self.assertNotIn("--dns", command)

    def test_rejects_non_canonical_hostname(self):
        with patch.object(m.os, "geteuid", return_value=0):
            for host in ("fi-test.mnebyvpn.site", "fi.mnebyvpn.site;id",
                         "a.fi.mnebyvpn.site", "fi.mnebyvpn.site.",
                         "fi.example.com", "FI.mnebyvpn.site"):
                with self.subTest(host=host), self.assertRaises(m.TLSStageError):
                    m.guarded_node(Path("/not-a-node"), "fi-test-01",
                                   host, "217.11.167.91", resolver=lambda *a,**k: [])

    def test_private_tls_files_created_with_strict_mode(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "privkey.pem"
            m.write_private(path, b"confidential-test-key")
            self.assertEqual(path.read_bytes(), b"confidential-test-key")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.is_symlink())

    def test_only_expected_fqdn_and_ipv4_are_accepted(self):
        self.assertTrue(m.COUNTRY_HOST.fullmatch("fi.mnebyvpn.site"))
        self.assertTrue(m.COUNTRY_HOST.fullmatch("nl.mnebyvpn.site"))
        self.assertIsNone(m.COUNTRY_HOST.fullmatch("fi-test.mnebyvpn.site"))


if __name__ == "__main__":
    unittest.main()
