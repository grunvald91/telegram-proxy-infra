"""Scope and no-activation regressions for RU188 isolated AWG systemd stage."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fi_awg_worker_isolated_systemd_stage as stage


class FiIsolatedSystemdStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "fi_awg_worker_isolated_systemd_stage.py").read_text()
        cls.workflow = (ROOT.parent / ".github/workflows/fi-awg-row-lock-gateway-stage.yml").read_text()

    def test_python_compiles(self):
        cp = subprocess.run(["python3", "-m", "py_compile", str(ROOT /
                             "fi_awg_worker_isolated_systemd_stage.py")],
                            capture_output=True, text=True, timeout=8)
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_gated_and_explicit_immutable_systemd_override(self):
        for expected in (
            "trust.require_safe_dormant()",
            "runtime.module_manifest_matches()",
            "runtime.isolated_module_import()",
            "source_verified()",
            "systemd_worker_not_dormant_disabled",
            "systemd_approval_flag_present",
            "approved_base_unit()",
            "unapproved_awg_unit_dropin",
            "existing_awg_dropin_drift",
            "exact_effective_unit()",
            "os.O_EXCL", "os.O_NOFOLLOW",
            '"daemon-reload"',
            "FI_AWG_ISOLATED_SYSTEMD=STAGED",
            "UNIT_DISABLED=true;WORKER_STARTED=false;CUSTOMER_RELEASE=false",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.text)
        self.assertIn("90-isolated-awg-worker.conf", self.text)
        self.assertIn("awg-worker-releases", str(stage.isolated.RELEASE))
        self.assertIn("ExecStart=\\n", self.text)
        self.assertEqual(stage.OVERRIDE.parent.name,
                         "mnebyvpn-awg-delivery.service.d")

    def test_not_an_activation_path(self):
        for forbidden in ("systemctl start", "systemctl enable",
                          "systemctl restart", "docker restart",
                          "iptables ", "wg set ",
                          "ALTER ROLE", "UPDATE public.", "INSERT INTO ",
                          "DELETE FROM ", "npm install", "pip install",
                          "open('/root/mnebyvpn-controller/controller-signing-key.pem'"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.text)

    def test_remote_stage_is_required_before_complete_preflight(self):
        self.assertIn("fi_awg_worker_isolated_systemd_stage.py", self.workflow)
        self.assertIn("FI_AWG_ISOLATED_SYSTEMD=STAGED;DROPIN=UNCHANGED", self.workflow)
        self.assertIn("PREACTIVATION_READY", self.workflow)
        self.assertIn("FI_AWG_ISOLATED_RUNTIME_ISOLATED_ESM_IMPORT", self.workflow)


if __name__ == "__main__":
    unittest.main()
