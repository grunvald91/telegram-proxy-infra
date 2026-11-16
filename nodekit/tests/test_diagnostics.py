import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control_plane import ContractError
from diagnostics import config_fingerprint, report


class Completed:
    returncode = 0


class DiagnosticContract(unittest.TestCase):
    def test_config_hash_only_no_raw_bytes(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "coredns.conf"
            f.write_text("example.com:853 { forward . 9.9.9.9 }\n")
            expected = hashlib.sha256(f.read_bytes()).hexdigest()
            result = config_fingerprint(f, expected)
            self.assertTrue(result["matches_known_good"])
            self.assertNotIn("example.com", str(result))
            self.assertFalse(config_fingerprint(f, "0"*64)["matches_known_good"])
            self.assertFalse(config_fingerprint(Path(t)/"missing", expected)["present"])

    def test_no_arbitrary_directory_hashing(self):
        for name in ("/etc/ssh/sshd_config",
                     "/etc/mnebyvpn-nodekit/../../ssh/sshd_config",
                     "/etc/mnebyvpn-nodekit/private.key"):
            with self.subTest(name=name), self.assertRaises(ContractError):
                report("de-node-01", {"bad": {"path": name, "sha256": "0"*64}},
                       lambda *args, **kwargs: Completed())

    def test_bounded_safe_metrics(self):
        out = report("de-node-01", {}, lambda *args, **kwargs: Completed())
        self.assertFalse(out["external_application_e2e_verified"])
        self.assertEqual(out["component_units"]["vpn"]["active"], True)
        self.assertNotIn("password", str(out).lower())
        self.assertNotIn("private_key", str(out).lower())


if __name__ == "__main__":
    unittest.main()
