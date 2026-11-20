"""Offline unit coverage for a nonactivating, rollback-safe FI217 systemd cutover."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fi_awg_worker_systemd_cutover as stage


class InactiveSystemdCutoverTests(unittest.TestCase):
    def legacy(self):
        oldroot = str(stage.isolated.RELEASE)
        return ("[Service]\nWorkingDirectory=" + oldroot +
                "\nExecStart=\nExecStart=/opt/mnebyvpn-controller/current/bin/node "
                "--experimental-strip-types " + oldroot +
                "/apps/service/src/awg-controller-delivery-worker.ts\n").encode()

    def prep(self, folder, *, rollback_failure=False):
        old = self.legacy()
        new = old.replace(str(stage.isolated.RELEASE).encode(),
                          str(stage.candidate.CANDIDATE).encode())
        unitdir = folder / "mnebyvpn-awg-delivery.service.d"
        unitdir.mkdir()
        unit = unitdir / "90-isolated-awg-worker.conf"
        unit.write_bytes(old)
        backups = folder / "backups"
        lock = folder / "cutover.lock"
        def test_reader(path, *unused):
            if not path.exists() or path.is_symlink():
                raise stage.trust.StageBlocked("missing")
            return path.read_bytes()
        def safe_mkdir(path):
            path.mkdir(parents=True, exist_ok=True)
        patchers = [
            mock.patch.object(stage, "OVERRIDE", unit),
            mock.patch.object(stage, "BACKUP_DIR", backups),
            mock.patch.object(stage, "BACKUP", backups / "fi217-old.backup"),
            mock.patch.object(stage, "LOCK", lock),
            mock.patch.object(stage.systemd, "DIR", unitdir),
            mock.patch.object(stage.systemd, "expected_dropin", return_value=old),
            mock.patch.object(stage.systemd, "dormant_and_disabled"),
            mock.patch.object(stage.systemd, "approved_base_unit"),
            mock.patch.object(stage.systemd, "source_verified"),
            mock.patch.object(stage.systemd, "exact_effective_unit"),
            mock.patch.object(stage.runtime, "node_checks"),
            mock.patch.object(stage, "verify_candidate_artifacts"),
            mock.patch.object(stage.trust, "read_file", side_effect=test_reader),
            mock.patch.object(stage.trust, "safe_directory"),
            mock.patch.object(stage.trust, "make_directory", side_effect=safe_mkdir),
            mock.patch.object(stage, "reload_definitions"),
        ]
        return old, new, unit, backups, patchers

    def run_patched(self, patchers, callback):
        active = [p.start() for p in patchers]
        try:
            return callback(active)
        finally:
            for p in reversed(patchers):
                p.stop()

    def test_new_dropin_only_changes_versioned_source_and_workdir(self):
        old = self.legacy()
        with mock.patch.object(stage.systemd, "expected_dropin", return_value=old):
            expected = stage.expected_new_dropin()
        self.assertEqual(
            expected, old.replace(str(stage.isolated.RELEASE).encode(),
                                  str(stage.candidate.CANDIDATE).encode()))
        self.assertNotIn(str(stage.isolated.RELEASE).encode(), expected)
        self.assertEqual(expected.count(str(stage.candidate.CANDIDATE).encode()), 2)
        self.assertIn(b"ExecStart=\n", expected)

    def test_switch_is_atomic_idempotent_with_pinned_old_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, new, unit, backups, patchers = self.prep(Path(tmp))
            with mock.patch.object(stage, "verified_new_effective_unit"):
                def run(_):
                    self.assertEqual(stage.switch(), "SWITCHED")
                    self.assertEqual(unit.read_bytes(), new)
                    self.assertEqual(next(backups.iterdir()).read_bytes(), old)
                    self.assertEqual(stage.switch(), "UNCHANGED")
                    stage.verify()
                self.run_patched(patchers, run)

    def test_invalid_postcondition_restores_old_file_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, new, unit, backups, patchers = self.prep(Path(tmp))
            with mock.patch.object(stage, "verified_new_effective_unit",
                                   side_effect=stage.trust.StageBlocked("wrong effective unit")):
                def run(active):
                    with self.assertRaises(stage.trust.StageBlocked):
                        stage.switch()
                    self.assertEqual(unit.read_bytes(), old)
                    self.assertEqual(next(backups.iterdir()).read_bytes(), old)
                    active[-1].assert_called_exactly if False else None
                    self.assertEqual(active[-1].call_count, 2)
                self.run_patched(patchers, run)

    def test_failed_preflight_blocks_writes_and_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, _, unit, backups, patchers = self.prep(Path(tmp))
            with mock.patch.object(stage.runtime, "node_checks",
                                   side_effect=stage.trust.StageBlocked("bad source")):
                def run(_):
                    with self.assertRaises(stage.trust.StageBlocked):
                        stage.switch()
                    self.assertEqual(unit.read_bytes(), old)
                    self.assertFalse(backups.exists())
                self.run_patched(patchers, run)

    def test_effective_worker_requires_single_exact_command_and_inactive_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            file = folder / "over.conf"
            file.write_bytes(b"expected\n")
            values = {
                "LoadState":"loaded",
                "FragmentPath":str(stage.systemd.BASE),
                "NeedDaemonReload":"no",
                "DropInPaths":str(file),
                "WorkingDirectory":str(stage.candidate.CANDIDATE),
                "ExecStart":("{ path=" + str(stage.NODE) +
                             " ; argv[]=" + str(stage.NODE) +
                             " --experimental-strip-types " + str(stage.ENTRY) +
                             " ; ignore_errors=no ; }"),
            }
            with mock.patch.object(stage, "OVERRIDE", file), \
                 mock.patch.object(stage.trust, "read_file",
                                   side_effect=lambda p, *args: p.read_bytes()), \
                 mock.patch.object(stage.systemd, "dormant_and_disabled"), \
                 mock.patch.object(stage.systemd, "approved_base_unit"), \
                 mock.patch.object(stage.systemd, "show", side_effect=lambda p: values[p]):
                stage.verified_new_effective_unit(b"expected\n")
                values["ExecStart"] += " ; argv[]=/bin/false"
                with self.assertRaises(stage.trust.StageBlocked):
                    stage.verified_new_effective_unit(b"expected\n")
                values["ExecStart"] = "argv[]=/bin/false"
                with self.assertRaises(stage.trust.StageBlocked):
                    stage.verified_new_effective_unit(b"expected\n")
                values["DropInPaths"] = str(file) + " /tmp/rogue.conf"
                with self.assertRaises(stage.trust.StageBlocked):
                    stage.verified_new_effective_unit(b"expected\n")

    def test_script_cannot_activate_unit_or_modify_release_flags(self):
        source = (ROOT / "fi_awg_worker_systemd_cutover.py").read_text()
        for forbidden in ("systemctl start", "systemctl enable",
                          "systemctl restart", "docker restart", "wg set ",
                          "UPDATE public.", "INSERT INTO ", "DELETE FROM "):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("cutover_rolled_back_after_failure", source)
        self.assertIn("os.replace(temp, OVERRIDE)", source)
        self.assertIn("os.fsync(file.fileno())", source)


if __name__ == "__main__":
    unittest.main()
