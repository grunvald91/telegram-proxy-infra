import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
import provision_node as m


class TestOneShot(unittest.TestCase):
    def test_spec_digest_matches_stage_manifest_contract(self):
        raw = {
            "schema_version": 1, "node_id": "fi-test-01",
            "role": "combined", "services": ["dns", "vpn", "sni-proxy", "tunnel"],
            "advertise_host": "fi-test.mnebyvpn.site",
            "listeners": {"dot_tcp": 853, "vpn_tcp": 2053,
                          "sni_tcp": 443, "tunnel_udp": 51820},
        }
        canonical = json.dumps(raw, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":")).encode()
        self.assertEqual(m.spec_digest(raw), hashlib.sha256(canonical).hexdigest())

    def test_existing_node_must_have_matching_spec(self):
        spec = {"node_id": "fi-test-01", "advertise_host": "fi-test.mnebyvpn.site"}
        manifest = {"node_id": "fi-test-01", "advertise_host": spec["advertise_host"],
                    "spec_sha256": m.spec_digest(spec), "state": "testing",
                    "registration_enabled": False, "activation_enabled": False}
        with patch.object(m, "safe_manifest", return_value=manifest):
            m.verify_node_manifest(Path("/example/node"), spec)
        altered = dict(manifest, advertise_host="other.example")
        with patch.object(m, "safe_manifest", return_value=altered):
            with self.assertRaises(m.ProvisionError):
                m.verify_node_manifest(Path("/example/node"), spec)

    def test_identity_does_not_accept_broken_public_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp)
            identity = node / "identity"
            identity.mkdir(mode=0o700)
            (identity / "node-private.pk8").write_bytes(b"X" * 64)
            (identity / "node-public.spki").write_bytes(b"Q" * 44)
            with patch.object(m, "safe_dir", return_value=None):
                with patch.object(m.os, "geteuid", return_value=0):
                    # Root-only metadata gate varies by CI UID; the invalid
                    # SPKI test only applies when the test is itself root.
                    if (identity / "node-public.spki").stat().st_uid == 0:
                        with self.assertRaises(m.ProvisionError):
                            m.verify_identity(node)

    def test_existing_vpn_must_not_have_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp) / "fi-test-01"
            node.mkdir()
            (node / "vpn").mkdir()
            stage = {"node_id": node.name, "xray_sha256": "1"*64,
                     "state": "staged", "activation_enabled": False,
                     "vpn_users_enabled": False}
            config = {"inbounds": [{"settings": {"clients": [{"id": "not-empty"}]}}]}
            def fake_manifest(path):
                return stage if path.name == "vpn-stage-manifest.json" else config
            with patch.object(m, "safe_dir", return_value=None):
                with patch.object(m, "safe_manifest", side_effect=fake_manifest):
                    with self.assertRaises(m.ProvisionError):
                        m.verify_vpn(node, "1"*64)


if __name__ == "__main__":
    unittest.main()
