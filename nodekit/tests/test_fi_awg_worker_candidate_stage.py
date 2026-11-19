"""Offline regression for nonpublishing FI217 AWG worker candidate staging."""
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
import fi_awg_worker_candidate_stage as candidate


class CandidateStagingTests(unittest.TestCase):
    def prepare(self, folder: Path, *, commit=candidate.CANDIDATE_COMMIT):
        manifest = {"commit": commit, "files": {}}
        for name in candidate.trust.FILES:
            body = ("import { readFileSync } from 'node:fs'; // " + name + "\n").encode()
            (folder / name).write_bytes(body)
            manifest["files"][name] = hashlib.sha256(body).hexdigest()
        (folder / "manifest.json").write_text(
            json.dumps(manifest, separators=(",", ":")) + "\n")
        return manifest

    def loaded(self, folder: Path):
        # Unprivileged test only: actual installation uses pinned RU188
        # root-owned file checks, never the mocked test reader.
        def readonly_test_reader(path, *args):
            if not path.exists() or path.is_symlink():
                candidate.trust.stop("source_file_missing_or_symlink")
            return path.read_bytes()
        with mock.patch.object(candidate.trust, "safe_directory"), mock.patch.object(
            candidate.trust, "read_file", side_effect=readonly_test_reader
        ):
            return candidate.candidate_blobs(folder)

    def test_exact_pinned_source_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.prepare(root)
            raw, blobs = self.loaded(root)
            self.assertIn(candidate.CANDIDATE_COMMIT.encode(), raw)
            self.assertEqual(set(blobs), set(candidate.trust.FILES.values()))

    def test_stale_or_tampered_commit_refused_before_any_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.prepare(root, commit=candidate.OLD_COMMIT)
            with self.assertRaises(candidate.trust.StageBlocked):
                self.loaded(root)
            self.prepare(root)
            source = root / "awg-controller-grants.ts"
            source.write_bytes(source.read_bytes() + b"// changed\n")
            with self.assertRaises(candidate.trust.StageBlocked):
                self.loaded(root)

    def test_missing_module_and_unreviewed_relative_import_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.prepare(root)
            (root / "awg-controller-outbox.ts").unlink()
            with self.assertRaises(candidate.trust.StageBlocked):
                self.loaded(root)
            self.prepare(root)
            bad = b"import '../unreviewed.ts';\n"
            (root / "awg-controller-outbox.ts").write_bytes(bad)
            manifest["files"]["awg-controller-outbox.ts"] = hashlib.sha256(bad).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest) + "\n")
            with self.assertRaises(candidate.trust.StageBlocked):
                self.loaded(root)

    def test_requires_old_verified_worker_dormant_and_no_cutover(self):
        with mock.patch.object(candidate.systemd, "dormant_and_disabled") as a, \
             mock.patch.object(candidate.systemd, "approved_base_unit") as b, \
             mock.patch.object(candidate.systemd, "exact_effective_unit") as c, \
             mock.patch.object(candidate.systemd, "source_verified") as d:
            candidate.guard()
            for fn in (a,b,c,d):
                fn.assert_called_once()
        self.assertTrue(candidate.STAGING.fullmatch("/run/fi-awg-worker-upgrade.aBcD1234"))
        self.assertFalse(candidate.STAGING.fullmatch("/tmp/fi-awg-worker-upgrade.aBcD1234"))
        self.assertFalse(candidate.STAGING.fullmatch("/run/fi-awg-worker-upgrade.aBcD1234/extra"))
        self.assertNotEqual(candidate.CANDIDATE_COMMIT,candidate.OLD_COMMIT)


if __name__ == "__main__":
    unittest.main()
