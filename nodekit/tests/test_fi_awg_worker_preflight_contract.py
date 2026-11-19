"""Read-only FI217 AWG worker preactivation audit contract."""
from pathlib import Path
import subprocess
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"fi_awg_worker_preflight.sh"

class FiAwgWorkerPreflightContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=SCRIPT.read_text()

    def test_script_parses_as_bash(self):
        result=subprocess.run(["bash","-n",str(SCRIPT)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_explicit_nonpublishing_status_and_fail_closed(self):
        self.assertIn("FI_AWG_PREFLIGHT=BLOCKED",self.source)
        self.assertIn("FI_AWG_PREFLIGHT=PREACTIVATION_READY",self.source)
        self.assertIn("WORKER_STARTED=false;CUSTOMER_RELEASE=false",self.source)
        self.assertIn("exit 2",self.source)
        self.assertIn("approval_absent",self.source)
        self.assertIn("worker_stopped",self.source)

    def test_no_mutating_operations(self):
        for forbidden in (
            "systemctl start ", "systemctl enable ", "ALTER ROLE ",
            "UPDATE public.", "INSERT INTO ", "DROP ", "chmod ",
            "chown ", "iptables ", "wg set ", "awg set ",
            "docker run ", "docker exec -i ", "docker exec -it ", "rm -rf ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,self.source)

    def test_workflow_requires_complete_markers_not_ssh_exit_alone(self):
        workflow=(Path(__file__).resolve().parents[2]/
                  ".github/workflows/fi-awg-row-lock-gateway-stage.yml").read_text()
        self.assertIn('preflight=$(ru \'bash -se\' < infra/nodekit/fi_awg_worker_preflight.sh)',workflow)
        self.assertIn("FI_AWG_PREFLIGHT=PREACTIVATION_READY;WORKER_STARTED=false;CUSTOMER_RELEASE=false",workflow)
        self.assertIn("audit_complete=false",workflow)
        self.assertIn("WORKER_RUNTIME APPROVAL_NOT_PRESENT WORKER_INACTIVE WORKER_NOT_ENABLED",workflow)
        self.assertIn("FI_AWG_WORKER_PREFLIGHT_STATUS=blocked",workflow)

    def test_expected_scoped_worker_dependencies(self):
        for expected in (
            "controller-public.spki", "fi-node-public.spki",
            "awg-delivery.env", "controller-signing-key.pem",
            "awg-delivery-known_hosts", "awg-delivery-ssh",
            "mnebyvpn-awg-delivery.service", "awg_worker_lock_node(text)",
            "vpn_awg_clients", "fi-test-01",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected,self.source)

if __name__=="__main__":
    unittest.main()
