"""Immutable FI217 AWG worker DB probe contract: reads only, never activates."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"fi_awg_worker_live_db_readonly.py"


class ReadonlyDbProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=PATH.read_text(encoding="utf-8")

    def test_python_syntax(self):
        result=subprocess.run(["python3","-m","py_compile",str(PATH)],
                              capture_output=True,text=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_actual_restricted_database_socket_and_no_workload(self):
        for expected in (
            "stage.dormant_and_disabled()",
            "stage.exact_effective_unit()",
            "stage.source_verified()",
            "runtime.trusted_node_binary()",
            "createRequire(release+'/apps/service/src/awg-controller-delivery-worker.ts')",
            "mnebyvpn_awg_delivery",
            "127\\.0\\.0\\.1:55433",
            "BEGIN READ ONLY", "ROLLBACK",
            "FI_AWG_DB_NODE_PROOF=",
            "FI_AWG_DB_RELEASE_DISABLED=PASS",
            "FI_AWG_DB_PROBE=READONLY_READY",
            "WORKER_STARTED=false;CUSTOMER_RELEASE=false",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected,self.source)

    def test_no_active_grants_billing_writes_or_sensitive_logs(self):
        for forbidden in (
            "systemctl start", "systemctl enable", "systemctl restart",
            "UPDATE public.", "INSERT INTO ", "DELETE FROM ", "ALTER ROLE",
            "CREATE ROLE", "DROP ", "GRANT ", "REVOKE ", "awg syncconf",
            "print(result.stderr)", "console.log(urls)", "console.log(env)",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,self.source)

    def test_status_is_strict_and_does_not_claim_customer_release(self):
        self.assertIn("if result.returncode or len(result.stdout) > 1024:",self.source)
        self.assertIn("len(lines) != 8",self.source)
        self.assertIn("FI_AWG_DB_NODE_PROOF=STALE",self.source)
        self.assertIn("FI_AWG_DB_NODE_PROOF=MISSING",self.source)
        self.assertIn("if(poolState.rows.length>1)fail();",self.source)
        self.assertIn("FI_AWG_DB_SQLSTATE=",self.source)
        self.assertIn("PRODUCTION_NODE_PROOF_FRESH=",self.source)
        self.assertIn("PRODUCTION_NODE_PROOF_FRESH=",self.source)
        self.assertIn("CUSTOMER_RELEASE=false",self.source)


if __name__=="__main__":
    unittest.main()
