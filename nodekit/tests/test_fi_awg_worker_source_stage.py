"""Offline tests for the RU188-only nonpublishing AWG worker source installer."""
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/"fi_awg_worker_source_stage.py"
SPEC=importlib.util.spec_from_file_location("fi_awg_worker_source_stage",PATH)
assert SPEC and SPEC.loader
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FiAwgWorkerSourceStageTests(unittest.TestCase):
    def test_source_compiles_and_does_not_activate(self):
        result=subprocess.run(["python3","-m","py_compile",str(PATH)],
                              capture_output=True,text=True,check=False,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr)
        source=PATH.read_text(encoding="utf-8")
        for forbidden in ("systemctl start ","systemctl enable ",
                          "ALTER ROLE ","UPDATE public.","INSERT INTO ",
                          "subscribers_published=true","docker exec -i "):
            self.assertNotIn(forbidden,source)
        self.assertIn('CURRENT = Path("/opt/mnebyvpn-controller/current")',source)
        self.assertIn("PINNED_COMMIT",source)
        self.assertIn("worker_is_not_inactive",source)
        self.assertIn("not_unpublished_enrolled_fi",source)

    def test_exact_five_file_source_allowlist(self):
        self.assertEqual(len(MODULE.FILES),5)
        self.assertEqual(set(MODULE.FILES.values()),{
            "apps/service/src/awg-controller-delivery-worker.ts",
            "packages/provisioning/src/awg-trusted-ssh-delivery.ts",
            "packages/provisioning/src/awg-offline-maintenance.ts",
            "packages/provisioning/src/awg-controller-grants.ts",
            "packages/provisioning/src/awg-controller-outbox.ts",
        })

    def manifest_fixture(self,malformed=None):
        blobs={name:b"import type { X } from 'pg';\n" for name in MODULE.FILES}
        if malformed is not None:
            blobs[next(iter(MODULE.FILES))]=malformed
        manifest={
            "commit":MODULE.PINNED_COMMIT,
            "files":{name:hashlib.sha256(raw).hexdigest() for name,raw in blobs.items()},
        }
        contents={"manifest.json":json.dumps(manifest).encode(),**blobs}
        return contents

    def approve_fixture(self,contents):
        with patch.object(MODULE,"safe_directory"), patch.object(
                MODULE,"read_file",side_effect=lambda path,limit=65536:
                contents[path.name]):
            return MODULE.approved_sources(Path("/run/fi-awg-row-lock.abcdefgh"))

    def test_exact_digest_manifest_accepted_only_for_reviewed_files(self):
        files=self.approve_fixture(self.manifest_fixture())
        self.assertEqual(len(files),5)
        tampered=self.manifest_fixture()
        tampered["awg-controller-outbox.ts"]=b"changed\n"
        with self.assertRaises(MODULE.StageBlocked):
            self.approve_fixture(tampered)

    def test_nul_or_missing_newline_never_accepted(self):
        for invalid in (b"import type { X } from 'pg';\x00\n",
                        b"import type { X } from 'pg';"):
            with self.subTest(value=invalid):
                with self.assertRaises(MODULE.StageBlocked):
                    self.approve_fixture(self.manifest_fixture(invalid))

    def test_unapproved_manifest_files_fail_closed(self):
        data=self.manifest_fixture()
        manifest=json.loads(data["manifest.json"])
        manifest["files"]["stray.ts"]="0"*64
        data["manifest.json"]=json.dumps(manifest).encode()
        with self.assertRaises(MODULE.StageBlocked):
            self.approve_fixture(data)


if __name__=="__main__":
    unittest.main()
