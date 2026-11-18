import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import awg_lifecycle as m


class TestAwgLifecycle(unittest.TestCase):
    def test_systemd_unit_never_enables_service_or_firewall(self):
        body=m.unit_source()
        self.assertIn("Type=oneshot",body)
        self.assertIn("RemainAfterExit=yes",body)
        self.assertIn("KillMode=control-group",body)
        self.assertIn("awg-quick up",body)
        self.assertIn("awg-quick down",body)
        self.assertIn("awg_lifecycle.py --node-id %i --mode validate",body)
        self.assertIn("WG_QUICK_USERSPACE_IMPLEMENTATION=",body)
        self.assertNotIn("iptables",body)
        self.assertNotIn("nft ",body)
        self.assertNotIn("PostUp",body)
        self.assertNotIn("enable --now",body)

    def test_malformed_node_id_rejected(self):
        for raw in ("../root","A","fi-test-01;shutdown","-fi","fi.1"):
            with self.subTest(raw=raw), self.assertRaises(m.AwgLifecycleError):
                m.unit_name(raw)
        self.assertEqual(m.unit_name("fi-test-01"),
                         "mnebyvpn-nodekit-awg@fi-test-01.service")

    def test_zero_peer_and_binary_hash_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            name=root.name
            config=(
                "[Interface]\nAddress = 10.73.91.1/24\n"
                "ListenPort = 51821\nHeaderProtectionKey = fake\n"
                "RandomTrailers = on\nTable = off\n"
            )
            (root / "manifest.json").write_text(json.dumps({
                "node_id": name, "state":"testing",
                "registration_enabled":False, "activation_enabled":False,
            }))
            awg=root / "amneziawg"
            awg.mkdir()
            (awg / "awg0.conf").write_text(config)
            report={
                "node_id":name,"state":"staged","protocol":"AmneziaWG 3.1",
                "activation_enabled":False,"peers_enabled":False,
                "subscribers_enabled":False,"port":51821,
                "config_sha256":hashlib.sha256(config.encode()).hexdigest(),
                "source_binary_sha256": {
                    "awg":"0"*64,"awg-quick":"1"*64,"amneziawg-go":"2"*64
                },
            }
            (awg/"manifest.json").write_text(json.dumps(report))
            with patch.object(m,"safe_manifest",side_effect=lambda p: json.loads(p.read_text())),\
                    patch.object(m,"checked_file",side_effect=lambda p: p.read_bytes()),\
                    patch.object(m,"safe_dir",return_value=None),\
                    patch.object(m,"AWG_BIN",root):
                with self.assertRaises(m.AwgLifecycleError):
                    m.validate(root)
                (awg/"awg0.conf").write_text(config + "[Peer]\nPublicKey = fake\n")
                with self.assertRaises(m.AwgLifecycleError):
                    m.validate(root)

    def test_canary_fails_closed_if_unit_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=pathlib.Path(tmp)
            with patch.object(m,"validate",return_value={"zero_peers":True}),\
                 patch.object(m,"UNIT_PATH",node / "unit"),\
                 patch.object(m,"APP",node / "app"),\
                 patch.object(m,"active_unit",return_value=False),\
                 patch.object(m,"enabled_unit",return_value=True):
                (node/"unit").write_text(m.unit_source())
                app=node/"app"
                app.mkdir()
                (app/"awg_lifecycle.py").write_bytes(pathlib.Path(m.__file__).read_bytes())
                with self.assertRaises(m.AwgLifecycleError):
                    m.canary(node)


if __name__ == "__main__":
    unittest.main()
