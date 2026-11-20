"""Offline regression for FI217 immutable policy source placement."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fi_awg_policy_source_stage as stage

class PolicyStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = {name: (ROOT / name).read_bytes() for name in stage.PINS}

    def test_pins_are_exact_reviewed_merged_git_blobs(self):
        for name, pin in stage.PINS.items():
            with self.subTest(name=name):
                self.assertEqual(stage.git_blob_id(self.payloads[name]), pin)

    def test_byte_changes_refused_before_placing_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            for name, data in self.payloads.items():
                (source / name).write_bytes(data)
            with mock.patch.object(stage, "checked_dir"), \
                 mock.patch.object(stage, "checked_file",
                                   side_effect=lambda path, **_: path.read_bytes()):
                self.assertEqual(stage.pinned_sources(source), self.payloads)
                (source / "awg_lifecycle.py").write_bytes(b"malicious")
                with self.assertRaises(stage.Blocked):
                    stage.pinned_sources(source)

    def test_atomic_versioned_placement_idempotent_and_drift_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            releases = Path(temp)
            with mock.patch.object(stage, "checked_dir"), \
                 mock.patch.object(stage, "checked_file",
                                   side_effect=lambda path, **_: path.read_bytes()):
                self.assertEqual(stage.stage_payloads(self.payloads, releases), "STAGED")
                release = releases / stage.RELEASE_NAME
                self.assertEqual({p.name for p in release.iterdir()}, set(stage.PINS))
                self.assertEqual(stage.stage_payloads(self.payloads, releases), "ALREADY_PRESENT")
                (release / "awg_lifecycle.py").write_bytes(b"modified")
                with self.assertRaises(stage.Blocked):
                    stage.stage_payloads(self.payloads, releases)
                self.assertEqual((release / "awg_lifecycle.py").read_bytes(), b"modified")

    def test_guard_fails_when_service_active_or_node_approved(self):
        document = {
            "node_id": stage.NODE, "advertise_host": "fi.mnebyvpn.site",
            "state": "testing", "activation_enabled": False,
            "registration_enabled": False,
        }
        def fake_run(*args, **kwargs):
            class Result:
                returncode=0
                stdout="2: eth0 inet 217.11.167.91/24 scope global eth0"
            return Result()
        with mock.patch.object(stage.os, "geteuid", return_value=0), \
             mock.patch.object(stage.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(stage, "checked_file",
                               return_value=json.dumps(document).encode()), \
             mock.patch.object(stage, "checked_dir"), \
             mock.patch.object(stage, "status_of", side_effect=["active", "disabled"]):
            with self.assertRaises(stage.Blocked):
                stage.live_guard()
        document["state"] = "active"
        with mock.patch.object(stage.os, "geteuid", return_value=0), \
             mock.patch.object(stage.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(stage, "checked_file",
                               return_value=json.dumps(document).encode()), \
             mock.patch.object(stage, "checked_dir"):
            with self.assertRaises(stage.Blocked):
                stage.live_guard()

    def test_no_runtime_switch_or_customer_release_code(self):
        source=(ROOT / "fi_awg_policy_source_stage.py").read_text()
        self.assertIn('RELEASE_NAME = "fi-awg-production-policy-1c500093"', source)
        self.assertNotIn('systemctl", "start"', source)
        self.assertNotIn('systemctl", "enable"', source)
        self.assertNotIn('vpn_release_flags SET', source)
        self.assertNotIn('iptables', source)
        self.assertNotIn('awg set', source)
        self.assertNotIn('os.replace(', source)
        self.assertIn('os.rename(scratch, release)', source)

if __name__ == "__main__":
    unittest.main()
