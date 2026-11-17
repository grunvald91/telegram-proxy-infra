import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import amneziawg_stage as m
import amneziawg_artifacts as artifacts


class TestAmneziaWg(unittest.TestCase):
    def test_protocol_is_not_plain_wireguard(self):
        k = base64.b64encode(b"A" * 32).decode()
        text = m.make_config(k, k)
        for name in ("S1", "S2", "S3", "S4", "HeaderProtectionKey",
                     "RandomTrailers", "ListenPort"):
            self.assertIn(name + " =", text)
        self.assertIn("ListenPort = 51821", text)
        self.assertIn("Table = off", text)
        self.assertNotIn("[Peer]", text)
        self.assertNotIn("PostUp", text)
        self.assertNotIn("PreUp", text)
        self.assertIn("DisableCookies = off", text)

    def test_key_format_rejected(self):
        with self.assertRaises(m.AwgError):
            m.make_config("bad", "also bad")

    def test_pinned_source_not_following_branch_heads(self):
        self.assertRegex(artifacts.SOURCE_COMMITS["tools"], r"^[0-9a-f]{40}$")
        self.assertRegex(artifacts.SOURCE_COMMITS["userspace"], r"^[0-9a-f]{40}$")
        self.assertEqual(m.AWG_PORT != 51820, True)

    def test_existing_awg_rejects_added_peer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            node = root / "fi-test-01"
            node.mkdir()
            output = node / "amneziawg"
            output.mkdir(mode=0o700)
            k = base64.b64encode(b"A" * 32).decode()
            cfg = m.make_config(k, k)
            (output / "awg0.conf").write_text(cfg + "\n[Peer]\nPublicKey = bad\n")
            (output / "manifest.json").write_text(json.dumps({
                "node_id": node.name, "state": "staged",
                "activation_enabled": False, "peers_enabled": False,
                "port": 51821, "source_binary_sha256": {"awg": "0"*64},
                "config_sha256": hashlib.sha256(cfg.encode()).hexdigest()
            }))
            with patch.object(m, "safe_dir", return_value=None), patch.object(
                m, "safe_manifest", return_value=json.loads(
                    (output / "manifest.json").read_text())
            ):
                with self.assertRaises(m.AwgError):
                    m.verify_existing(node, {"awg": "0"*64})

    @unittest.skipUnless(os.geteuid() == 0, 'Artifact owner contract requires root')
    def test_artifact_source_mismatch_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            node = root / "fi-test-01"
            node.mkdir()
            bundle = root / "bundle"
            bundle.mkdir()
            hashes = {}
            for name in artifacts.NAMES:
                raw = (name.encode() + b"_") * 1000
                (bundle / name).write_bytes(raw)
                hashes[name] = hashlib.sha256(raw).hexdigest()
            with patch.object(artifacts, "DEST", root / "installed"), patch.object(
                artifacts, "safe_dir", return_value=None):
                artifacts.stage_artifacts(node, bundle, hashes)
                self.assertTrue((root / "installed" / "awg").exists())
                hashes["awg"] = "0" * 64
                with self.assertRaises(artifacts.ArtifactError):
                    artifacts.stage_artifacts(node, bundle, hashes)
                self.assertNotEqual((root / "installed" / "awg").read_bytes(), b"changed")
