"""Offline fail-closed contracts for RU188 immutable pg dependency stage."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_pg_stage as pgstage

PATH=ROOT/"fi_awg_worker_isolated_pg_stage.py"


class IsolatedPgStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=PATH.read_text(encoding="utf-8")

    def test_source_compiles(self):
        run=subprocess.run(["python3","-m","py_compile",str(PATH)],
                           capture_output=True,text=True,timeout=8)
        self.assertEqual(run.returncode,0,run.stderr)

    def test_root_only_bounded_production_copy(self):
        for text in ("trust.require_safe_dormant()", "runtime.module_manifest_matches()",
                     '"8.16.3"', "MAX_PACKAGES = 40",
                     "MAX_FILES = 2500", "MAX_BYTES = 24",
                     "MAX_FILE_BYTES = 1024",
                     "os.O_EXCL", "os.O_NOFOLLOW",
                     "existing_isolated_package_drift",
                     "partial_dependency_stage_with_manifest",
                     "FI_AWG_ISOLATED_PG=STAGED",
                     "WORKER_STARTED=false;CUSTOMER_RELEASE=false"):
            with self.subTest(text=text):
                self.assertIn(text,self.source)
        self.assertEqual(pgstage.MODULES,pgstage.isolated.RELEASE/"node_modules")

    def test_no_live_service_or_repo_changes(self):
        for dangerous in ("systemctl start ","systemctl enable ",
                          "systemctl restart ", "docker restart ",
                          "npm install", "pip install", "curl ",
                          "UPDATE public.", "INSERT INTO ", "DELETE FROM ",
                          "os.symlink(", "subprocess.run("):
            with self.subTest(dangerous=dangerous):
                self.assertNotIn(dangerous,self.source)

    def test_rejects_untrusted_dependency_names(self):
        for value in ("../etc","./pg","/tmp","a/../../b","",
                      "@a/../b","pg;rm","A/B"):
            with self.subTest(value=value):
                with self.assertRaises(trust.StageBlocked):
                    pgstage.package_name(value)
        for value in ("pg","pg-connection-string","@test/utility"):
            self.assertEqual(pgstage.package_name(value),value)

    def test_manifest_declared_only_dependencies(self):
        req,opt=pgstage.dependencies({
            "dependencies":{"pg-protocol":"^1.0.0"},
            "optionalDependencies":{"pg-cloudflare":"^1.0.0"},
        })
        self.assertEqual(req,{"pg-protocol"})
        self.assertEqual(opt,{"pg-cloudflare"})
        with self.assertRaises(trust.StageBlocked):
            pgstage.dependencies({"dependencies":{"../../escape":"*"}})


if __name__=="__main__":
    unittest.main()
