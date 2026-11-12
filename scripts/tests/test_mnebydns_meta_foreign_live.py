#!/usr/bin/env python3
"""Reversible Meta-family canary guardrails, no remote server involved."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/"scripts/mnebydns-meta-foreign-live-20261112.py"
spec=importlib.util.spec_from_file_location("meta_live",SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class MetaLiveTests(unittest.TestCase):
    def test_approval_before_any_server_read(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(RuntimeError,"not approved"):
                mod.deploy("43260000000",Path("/absent"))

    def test_bad_run_id_rejected(self):
        for item in ("0","root","1;rm -rf /","1234567","9999999999999999999999"):
            self.assertIsNone(mod.RUN_RE.fullmatch(item),item)
        self.assertIsNotNone(mod.RUN_RE.fullmatch("43260000000"))

    def test_conflicting_owner_timer_blocks(self):
        with patch.object(mod,"cmd",return_value="Thu 2026 owner mnebydns-owner-rollback-123.timer") as c:
            with self.assertRaisesRegex(RuntimeError,"Owner DNS timer"):
                mod.owner_quiescent()
            self.assertIn("--no-legend",c.call_args[0])
            self.assertNotIn("--all",c.call_args[0])

    def test_no_other_meta_release_pending(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"123456789"/"pending").parent.mkdir()
            (root/"123456789"/"pending").write_text("canary")
            with patch.object(mod,"RUNROOT",root),patch.object(mod,"cmd",return_value=""):
                with self.assertRaisesRegex(RuntimeError,"Another Meta canary"):
                    mod.owner_quiescent()

    def test_atomic_write_preserves_owner_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"test.conf"
            p.write_bytes(b"old")
            p.chmod(0o600)
            mod.write_atomically(p,b"new")
            self.assertEqual(p.read_bytes(),b"new")
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertFalse((Path(d)/"test.conf.meta-candidate-tmp").exists())

    def test_rollback_refuses_external_drifts(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            paths={x:root/(x+".live") for x in ("dns","nginx","proxy")}
            backup=root/"run";backup.mkdir()
            (backup/"pending").write_text("1")
            for name,p in paths.items():
                p.write_bytes(b"external owner changed")
                (backup/(name+".before")).write_bytes(b"original")
                (backup/(name+".candidate")).write_bytes(b"meta candidate")
            with patch.object(mod,"LIVE",paths):
                with self.assertRaisesRegex(RuntimeError,"concurrent config drift"):
                    mod.restore_unlocked(backup)
            for p in paths.values():
                self.assertEqual(p.read_bytes(),b"external owner changed")

    def test_rollback_confirmed_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)
            (base/"pending").write_text("canary")
            (base/"confirmed").write_text("promoted")
            with patch.object(mod,"LIVE",{}):
                mod.restore_unlocked(base)
            self.assertTrue((base/"pending").exists())

    def test_rollback_unchanged_no_restart(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            paths={x:root/(x+".live") for x in ("dns","nginx","proxy")}
            base=root/"run";base.mkdir()
            (base/"pending").write_text("canary")
            for name,p in paths.items():
                p.write_bytes(b"original")
                (base/(name+".before")).write_bytes(b"original")
                (base/(name+".candidate")).write_bytes(b"candidate")
            with patch.object(mod,"LIVE",paths),patch.object(mod,"cmd",return_value=""),patch.object(mod,"check_services",return_value=None):
                mod.restore_unlocked(base)
            self.assertFalse((base/"pending").exists())
            self.assertTrue((base/"restored").exists())

    def test_no_packet_modification_commands(self):
        src=SCRIPT.read_text()
        for value in ("tcp_window_scaling=","nft -f","iptables ","nfqueue",
                      "split ClientHello","sysctl -w"):
            self.assertNotIn(value,src)
        self.assertIn("OnCalendar=",src)
        self.assertIn("Persistent=true",src)
        self.assertIn("mnebydns-googlepilot.service",src)

if __name__=="__main__":
    unittest.main()
