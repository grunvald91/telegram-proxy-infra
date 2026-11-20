"""FI217 signed production egress staged immutably, never active."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_egress_source_stage as m

class Tests(unittest.TestCase):
    def test_blob_pin_matches_real_reviewed_egress(self):
        data=(Path(__file__).parents[1]/"awg_egress.py").read_bytes()
        self.assertEqual(m.git_blob_id(data),m.PIN)

    def test_safe_staging_repeated_and_fails_closed_on_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            src=folder/"src"
            src.write_bytes((Path(__file__).parents[1]/"awg_egress.py").read_bytes())
            release=folder/"releases"
            release.mkdir()
            def data(path,**_):return path.read_bytes()
            with patch.object(m,"checked_dir"),patch.object(m,"checked_file",side_effect=data):
                self.assertEqual(m.stage(src,release),"STAGED")
                self.assertEqual(m.stage(src,release),"ALREADY_PRESENT")
                m.verify(release)
                (release/m.NAME/"awg_egress.py").write_bytes(b"tampered")
                with self.assertRaises(m.Blocked):
                    m.verify(release)
                with self.assertRaises(m.Blocked):
                    m.stage(src,release)

    def test_refuses_unreviewed_source_and_does_not_create_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            source=folder/"bad";source.write_bytes(b"wrong source")
            with patch.object(m,"checked_dir"),patch.object(m,"checked_file",side_effect=lambda path,**_:path.read_bytes()):
                with self.assertRaises(m.Blocked):
                    m.stage(source,folder)
            self.assertFalse((folder/m.NAME).exists())

    def test_dormant_guard_checks_watchdog_and_egress(self):
        from types import SimpleNamespace
        states=[SimpleNamespace(returncode=0,stdout="inactive\n"),
                SimpleNamespace(returncode=0,stdout="active\n")]
        with patch.object(m,"live_guard"),patch.object(m.subprocess,"run",side_effect=states):
            with self.assertRaises(m.Blocked):
                m.require_dormant()

    def test_no_runtime_switch_or_firewall_updates_in_stager(self):
        source=(Path(__file__).parents[1]/"fi_awg_egress_source_stage.py").read_text()
        self.assertIn("require_dormant()",source)
        self.assertIn('CODE_SWITCHED=false',source)
        self.assertNotIn('systemctl", "start"',source)
        self.assertNotIn('iptables", "-I"',source)
        self.assertNotIn('vpn_release_flags SET',source)

if __name__=="__main__":unittest.main()
