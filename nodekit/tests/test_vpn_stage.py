import importlib.util
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "vpn_stage.py"
spec = importlib.util.spec_from_file_location("nodekit_vpn_stage", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Completed:
    def __init__(self, stdout=b"", rc=0):
        self.stdout = stdout
        self.returncode = rc


class VpnStageContract(unittest.TestCase):
    def prepare(self, t):
        root = Path(t) / "staged"
        root.mkdir(mode=0o700)
        node_id = "de-node-02"
        node = root / node_id
        node.mkdir(mode=0o700)
        (node / "identity").mkdir(mode=0o700)
        (node / "identity" / "node-public.spki").write_bytes(m.PREFIX_ED25519_SPKI + b"\x01" * 32)
        (node / "manifest.json").write_text(json.dumps({
            "node_id": node_id,
            "advertise_host": "de-node-02.nodes.example.net",
            "state": "testing",
            "registration_enabled": False,
            "activation_enabled": False,
            "roles": ["dns", "vpn", "sni-proxy", "tunnel"],
            "listeners": {"vpn_tcp": 2053},
        }))
        binary = Path(t) / "xray"
        binary.write_bytes(b"xray-pinned-binary:" + b"x" * 20000)
        binary.chmod(0o700)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        return root, node_id, binary, digest

    def runner(self, args, **kwargs):
        if args[-1] == "x25519":
            private = base64.urlsafe_b64encode(b"\x03" * 32).rstrip(b"=").decode()
            return Completed(("Private key: " + private + "\n").encode("ascii"))
        if args[1] == "pkey":
            return Completed(m.PREFIX_X25519_SPKI + b"\x04" * 32)
        if args[1:4] == ["run", "-test", "-config"]:
            cfg = json.loads(Path(args[4]).read_text())
            assert cfg["inbounds"][0]["settings"]["clients"] == []
            assert cfg["inbounds"][0]["streamSettings"]["security"] == "reality"
            return Completed()
        raise AssertionError("Unexpected invoked command")

    def test_stage_only_creates_isolated_unpublished_config(self):
        with tempfile.TemporaryDirectory() as t:
            root, node_id, binary, digest = self.prepare(t)
            report = m.stage_vpn(root, node_id, binary, digest,
                                 require_root=False, runner=self.runner)
            self.assertEqual(report["state"], "staged")
            self.assertEqual(report["vpn_port"], 2053)
            self.assertFalse(report["activation_enabled"])
            self.assertFalse(report["vpn_users_enabled"])
            self.assertFalse(report["independent_e2e_verified"])
            self.assertNotIn("privateKey", json.dumps(report))
            state = root / node_id / "vpn"
            self.assertTrue((state / "vpn-stage-manifest.json").is_file())
            config = state / "xray-config.json"
            self.assertTrue(config.is_file())
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            private_conf = json.loads(config.read_text())
            self.assertEqual(private_conf["inbounds"][0]["settings"]["clients"], [])
            self.assertEqual(private_conf["inbounds"][0]["port"], 2053)
            self.assertEqual(private_conf["outbounds"][0]["protocol"], "freedom")
            self.assertEqual(len(list(state.iterdir())), 2)
            with self.assertRaises(m.VpnStageError):
                m.stage_vpn(root, node_id, binary, digest,
                            require_root=False, runner=self.runner)

    def test_staging_denies_unpinned_binary_or_identity(self):
        with tempfile.TemporaryDirectory() as t:
            root, node_id, binary, digest = self.prepare(t)
            with self.assertRaises(m.VpnStageError):
                m.stage_vpn(root, node_id, binary, "0" * 64,
                            require_root=False, runner=self.runner)
            self.assertFalse((root / node_id / "vpn").exists())
            manifest = root / node_id / "manifest.json"
            data = json.loads(manifest.read_text())
            data["activation_enabled"] = True
            manifest.write_text(json.dumps(data))
            with self.assertRaises(m.VpnStageError):
                m.stage_vpn(root, node_id, binary, digest,
                            require_root=False, runner=self.runner)
            self.assertFalse((root / node_id / "vpn").exists())

    def test_atomic_promotion_never_replaces_preexisting_vpn_state(self):
        with tempfile.TemporaryDirectory() as t:
            root, node_id, binary, digest = self.prepare(t)
            existing = root / node_id / "vpn"
            existing.mkdir(mode=0o700)
            (existing / "keep.txt").write_text("do-not-overwrite")
            with self.assertRaises(m.VpnStageError):
                m.stage_vpn(root, node_id, binary, digest,
                            require_root=False, runner=self.runner)
            self.assertEqual((existing / "keep.txt").read_text(),
                             "do-not-overwrite")
            tmp = existing.parent / ".vpn-stage-standin"
            tmp.mkdir()
            with self.assertRaises(FileExistsError):
                m._promote_stage_noreplace(tmp, existing)
            self.assertTrue(tmp.is_dir())

    def test_bad_xray_validation_rolls_back_staging(self):
        with tempfile.TemporaryDirectory() as t:
            root, node_id, binary, digest = self.prepare(t)
            def runner(args, **kwargs):
                if args[1:4] == ["run", "-test", "-config"]:
                    raise RuntimeError("Rejected config")
                return self.runner(args, **kwargs)
            with self.assertRaises(RuntimeError):
                m.stage_vpn(root, node_id, binary, digest,
                            require_root=False, runner=runner)
            self.assertFalse((root / node_id / "vpn").exists())
            self.assertFalse(list((root / node_id).glob(".vpn-stage-*")))


if __name__ == "__main__":
    unittest.main()
