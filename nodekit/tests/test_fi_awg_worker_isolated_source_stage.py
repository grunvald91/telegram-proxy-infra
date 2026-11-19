"""Nonpublishing isolated RU188 AWG source-release regression checks."""
from pathlib import Path
import importlib.util
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_worker_isolated_source_stage as stage
import fi_awg_worker_source_stage as trust


class IsolatedAwgReleaseTests(unittest.TestCase):
    def test_compiles_and_only_writes_in_isolated_release(self):
        script=ROOT/"fi_awg_worker_isolated_source_stage.py"
        proc=subprocess.run(["python3","-m","py_compile",str(script)],
                            text=True,capture_output=True,check=False,timeout=10)
        self.assertEqual(proc.returncode,0,proc.stderr)
        source=script.read_text()
        self.assertIn('RELEASES = Path("/opt/mnebyvpn-controller/awg-worker-releases")',source)
        self.assertIn("trust.require_safe_dormant()",source)
        self.assertIn("trust.approved_sources(source)",source)
        self.assertIn('RUNTIME_ATTACHED=false',source)
        for forbidden in ("systemctl start ","systemctl enable ",
                          "UPDATE public.","ALTER ROLE ","INSERT INTO ",
                          "CURRENT / rel", "node_modules").__iter__():
            if forbidden=="node_modules":
                self.assertIn("No node_modules symlink or runtime is attached",source)
            else:
                self.assertNotIn(forbidden,source)
        self.assertIn("os.O_EXCL",source)
        self.assertIn("os.O_NOFOLLOW",source)
        self.assertIn("partial_isolated_release_with_manifest",source)

    def test_accepts_exact_relative_pinned_graph(self):
        blobs={
            "apps/service/src/awg-controller-delivery-worker.ts":
                b"import {x} from '../../../packages/provisioning/src/awg-trusted-ssh-delivery.ts';\nimport {Pool} from 'pg';\n",
            "packages/provisioning/src/awg-trusted-ssh-delivery.ts":
                b"import {sign} from 'node:crypto';\n",
        }
        stage.require_source_closure(blobs)

    def test_rejects_missing_relative_dependency(self):
        blob={"apps/service/src/awg-controller-delivery-worker.ts":
              b"import {x} from './not-pinned.ts';\n"}
        with self.assertRaises(trust.StageBlocked):
            stage.require_source_closure(blob)

    def test_rejects_unapproved_external_package(self):
        blob={"apps/service/src/awg-controller-delivery-worker.ts":
              b"import {x} from 'other-unknown-package';\n"}
        with self.assertRaises(trust.StageBlocked):
            stage.require_source_closure(blob)

    def test_rejects_relative_import_outside_release(self):
        blob={"apps/service/src/awg-controller-delivery-worker.ts":
              b"import {x} from '../../../../../../escape.ts';\n"}
        with self.assertRaises(trust.StageBlocked):
            stage.require_source_closure(blob)

if __name__=="__main__":
    unittest.main()
