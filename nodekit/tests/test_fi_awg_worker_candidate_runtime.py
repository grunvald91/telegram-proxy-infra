"""Unit tests for non-activating FI217 corrected worker runtime installation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fi_awg_worker_candidate_runtime as runtime
import fi_awg_worker_candidate_stage as candidate


class CorrectedWorkerRuntimeTests(unittest.TestCase):
    def test_manifest_exact_pinned_commit_and_digests(self):
        packages = {"pg":"8.16.3","pg-protocol":"1.8.0"}
        blobs = {
            "pg/package.json":b'{"name":"pg","version":"8.16.3"}',
            "pg-protocol/package.json":b'{"name":"pg-protocol","version":"1.8.0"}',
        }
        raw = runtime.expected_runtime(blobs, packages)
        data = json.loads(raw)
        self.assertEqual(data["commit"], candidate.CANDIDATE_COMMIT)
        self.assertEqual(data["packages"], packages)
        self.assertEqual(data["files"]["pg/package.json"],
                         hashlib.sha256(blobs["pg/package.json"]).hexdigest())
        self.assertTrue(raw.endswith(b"\n"))

    def test_rejects_wrong_commit_and_dependency_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blob = b'{"name":"pg","version":"8.16.3"}'
            (root/"node_modules"/"pg").mkdir(parents=True)
            (root/"node_modules"/"pg"/"package.json").write_bytes(blob)
            marker = {
                "commit":candidate.CANDIDATE_COMMIT,
                "packages":{"pg":"8.16.3"},
                "files":{"pg/package.json":hashlib.sha256(blob).hexdigest()},
            }
            path = root/"awg-pg-runtime-manifest.json"
            def reader(p, *args):
                if not p.exists() or p.is_symlink():
                    raise runtime.trust.StageBlocked("missing")
                return p.read_bytes()
            with mock.patch.object(runtime, "MARKER", path), \
                 mock.patch.object(runtime, "MODULES", root/"node_modules"), \
                 mock.patch.object(runtime, "verified_sources"), \
                 mock.patch.object(runtime.trust, "read_file", side_effect=reader):
                path.write_text(json.dumps(marker))
                runtime.verify_runtime_manifest()
                marker["commit"] = candidate.OLD_COMMIT
                path.write_text(json.dumps(marker))
                with self.assertRaises(runtime.trust.StageBlocked):
                    runtime.verify_runtime_manifest()
                marker["commit"] = candidate.CANDIDATE_COMMIT
                path.write_text(json.dumps(marker))
                (root/"node_modules"/"pg"/"package.json").write_bytes(b"tampered")
                with self.assertRaises(runtime.trust.StageBlocked):
                    runtime.verify_runtime_manifest()

    def test_version_check_and_import_do_not_start_worker(self):
        with mock.patch.object(runtime, "verify_runtime_manifest") as manifest, \
             mock.patch.object(runtime.runtime, "version_compatible") as version, \
             mock.patch.object(runtime.runtime, "trusted_node_binary", return_value=Path("/node")), \
             mock.patch.object(runtime.runtime, "command_ok") as check:
            runtime.node_checks()
            manifest.assert_called_once()
            version.assert_called_once()
            commands = [a.args[0] for a in check.call_args_list]
            self.assertEqual(len(commands), len(runtime.trust.FILES) + 1)
            self.assertTrue(all("--check" in line for line in commands[:-1]))
            self.assertIn("__AWG_IMPORT_ONLY__", commands[-1])
            self.assertEqual(commands[-1][-1], str(runtime.ENTRY))

    def test_runtime_targets_distinct_candidate_and_never_effective_release(self):
        self.assertEqual(runtime.RELEASE, candidate.CANDIDATE)
        self.assertNotEqual(runtime.RELEASE, runtime.isolated.RELEASE)
        self.assertNotEqual(runtime.MODULES, runtime.pgstage.MODULES)
        with mock.patch.object(runtime, "node_checks") as checked, \
             mock.patch.object(runtime.candidate, "guard") as guard:
            with mock.patch.object(sys,"argv",["script", "--mode", "verify"]):
                self.assertEqual(runtime.main(), 0)
            checked.assert_called_once()
            guard.assert_called_once()


if __name__ == "__main__":
    unittest.main()
