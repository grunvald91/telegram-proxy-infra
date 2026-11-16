import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

M = Path(__file__).resolve().parents[1] / "nodekit.py"
module_spec = importlib.util.spec_from_file_location("nodekit", M)
nodekit = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(nodekit)

BASE = {
    "schema_version": 1,
    "node_id": "de-frankfurt-02",
    "role": "combined",
    "services": ["dns", "vpn", "sni-proxy", "tunnel"],
    "advertise_host": "node02.example.net",
    "listeners": {
        "dot_tcp": 853, "vpn_tcp": 2053, "sni_tcp": 443, "tunnel_udp": 51820
    },
}


class TestNodekit(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(nodekit.validate_spec(BASE)["role"], "combined")

    def test_reject_bad_spec(self):
        bad = [
            {**BASE, "node_id": "../root"},
            {**BASE, "role": "unknown"},
            {**BASE, "services": ["dns", "dns"]},
            {**BASE, "services": [1, 2]},
            {**BASE, "advertise_host": "89.125.90.101"},
            {**BASE, "advertise_host": "localhost"},
            {**BASE, "listeners": {**BASE["listeners"], "other": 42}},
            {**BASE, "listeners": {**BASE["listeners"], "vpn_tcp": 443}},
            {**BASE, "listeners": {**BASE["listeners"], "sni_tcp": True}},
            {**BASE, "extra": "unexpected"},
            {**BASE, "role": "edge"},
        ]
        for entry in bad:
            with self.subTest(entry=entry), self.assertRaises(nodekit.SpecError):
                nodekit.validate_spec(entry)

    def test_staging_atomic_no_overwrite(self):
        report = {"can_stage": True}
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"
            output = nodekit.stage(BASE, report, root)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertFalse(manifest["activation_enabled"])
            self.assertFalse(manifest["registration_enabled"])
            self.assertEqual(manifest["state"], "testing")
            self.assertEqual(manifest["advertise_host"], BASE["advertise_host"])
            self.assertEqual(manifest["listeners"]["vpn_tcp"], 2053)
            with self.assertRaises(nodekit.SpecError):
                nodekit.stage(BASE, report, root)

    def test_atomic_promotion_never_replaces_existing_stage(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            staged = root / "temporary"
            target = root / "live"
            staged.mkdir()
            target.mkdir()
            (target / "keep.txt").write_text("not-owned-by-nodekit")
            with self.assertRaises(FileExistsError):
                nodekit._promote_stage_noreplace(staged, target)
            self.assertEqual((target / "keep.txt").read_text(),
                             "not-owned-by-nodekit")
            self.assertTrue(staged.exists())

    def test_refuse_symlink_spec(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "spec.json"
            file.write_text(json.dumps(BASE))
            link = Path(t) / "link.json"
            link.symlink_to(file)
            with self.assertRaises(nodekit.SpecError):
                nodekit.load_spec(link)

    def test_preflight_gate_for_occupied_port(self):
        with (
            patch.object(nodekit, "system_facts", return_value={
                "os_id": "debian", "os_version": "13", "architecture": "x86_64",
                "disk_free_gib": 10, "has_systemd": True,
            }),
            patch.object(nodekit, "check_ports", return_value={
                "dot_tcp": "occupied_or_unavailable"
            }),
        ):
            report = nodekit.compute_report(BASE)
            self.assertFalse(report["can_stage"])
            self.assertFalse(report["registration_enabled"])


if __name__ == "__main__":
    unittest.main()
