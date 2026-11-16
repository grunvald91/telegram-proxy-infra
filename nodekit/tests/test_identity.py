import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

MOD = Path(__file__).resolve().parents[1] / "identity.py"
s = importlib.util.spec_from_file_location("nodekit_identity", MOD)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class IdentityContract(unittest.TestCase):
    def test_unique_private_key_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "nodekit"
            root.mkdir(mode=0o700)
            for identifier in ("de-node-02", "nl-node-03"):
                node = root / identifier
                node.mkdir(mode=0o700)
                (node / "manifest.json").write_text(json.dumps({
                    "node_id": identifier,
                    "state": "testing",
                    "registration_enabled": False,
                    "advertise_host": identifier + ".example.net",
                }))
                (node / "manifest.json").chmod(0o600)
            de = m.create_identity(root, "de-node-02", require_root=False)
            nl = m.create_identity(root, "nl-node-03", require_root=False)
            self.assertNotEqual(de["identity_public_spki"], nl["identity_public_spki"])
            self.assertEqual(len(de["identity_public_spki"]), 59)
            self.assertEqual(len(de["identity_public_sha256"]), 64)
            self.assertFalse(de["enabled"])
            self.assertFalse(de["enrolled"])
            for identifier in ("de-node-02", "nl-node-03"):
                key = root / identifier / "identity" / "node-private.pk8"
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                self.assertGreater(key.stat().st_size, 40)
                # Verify that the new private key is parsable by OpenSSL.
                completed = subprocess.run(
                    ["openssl", "pkey", "-inform", "DER", "-in", str(key),
                     "-noout"], capture_output=True, timeout=3)
                self.assertEqual(completed.returncode, 0)
            with self.assertRaises(FileExistsError):
                m.create_identity(root, "de-node-02", require_root=False)
            with self.assertRaises(m.IdentityError):
                m.create_identity(root, "bad../", require_root=False)

    def test_reject_unstaged_untrusted_node(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "nodekit"
            root.mkdir(mode=0o700)
            node = root / "de-node-02"
            node.mkdir(mode=0o700)
            manifest = node / "manifest.json"
            manifest.write_text(json.dumps({
                "node_id": "de-node-02", "state": "enabled",
                "registration_enabled": True,
                "advertise_host": "de-node-02.example.net",
            }))
            manifest.chmod(0o600)
            with self.assertRaises(m.IdentityError):
                m.create_identity(root, "de-node-02", require_root=False)
            self.assertFalse((node / "identity").exists())


if __name__ == "__main__":
    unittest.main()
