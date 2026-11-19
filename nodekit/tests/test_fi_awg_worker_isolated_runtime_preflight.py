"""Offline contract checks for RU188 AWG isolated Node runtime inspection."""
from pathlib import Path
import subprocess
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"fi_awg_worker_isolated_runtime_preflight.py"


class IsolatedAwgRuntimePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=SCRIPT.read_text()

    def test_script_compiles(self):
        result=subprocess.run(["python3","-m","py_compile",str(SCRIPT)],
                              capture_output=True,text=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_checks_pinned_manifest_and_ts_syntax(self):
        for fragment in ("trust.require_safe_dormant",
                         "trust.PINNED_COMMIT", "trust.read_file",
                         "isolated.require_source_closure",
                         '"--experimental-strip-types", "--check"',
                         "require.resolve('pg'",
                         "NODE_VERSION", "SOURCE_MANIFEST",
                         "TYPESCRIPT_SYNTAX", "SHARED_PG_RESOLUTION"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment,self.source)

    def test_never_starts_service_or_modifies_customer_state(self):
        for fragment in ("systemctl start","systemctl restart","systemctl enable",
                         "ALTER ROLE","UPDATE public.","INSERT INTO ",
                         "os.symlink(", "os.mkdir(", "os.makedirs(",
                         "CURRENT / rel", "publishSubscribers("):
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment,self.source)
        self.assertIn("RUNTIME_ATTACHED=false",self.source)
        self.assertIn("WORKER_STARTED=false",self.source)
        self.assertIn("CUSTOMER_RELEASE=false",self.source)

    def test_fail_closed_status(self):
        self.assertIn("FI_AWG_ISOLATED_RUNTIME_PREFLIGHT=READONLY_READY",self.source)
        self.assertIn("FI_AWG_ISOLATED_RUNTIME_PREFLIGHT=BLOCKED",self.source)
        self.assertIn("if not all(outcome)",self.source)
        self.assertIn("return 2",self.source)


if __name__=="__main__":
    unittest.main()
