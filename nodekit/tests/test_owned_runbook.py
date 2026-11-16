import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control_plane import ContractError, canonical
from owned_runbook import execute, verify_permit

NOW = datetime.now(timezone.utc).replace(microsecond=0)
KEY = b"a" * 32


def permit(node="de-node-01", service="vpn", action="restart-owned-sidecar"):
    fields = {
        "operation_id": str(uuid4()), "incident_id": str(uuid4()),
        "node_id": node, "service": service,
        "reason_code": "OWNED_UNIT_INACTIVE", "action": action,
        "issued_at": NOW.isoformat(), "expires_at": (NOW+timedelta(seconds=90)).isoformat()
    }
    return {**fields, "mac": hmac.new(KEY, canonical(fields), hashlib.sha256).hexdigest()}


class Completed:
    def __init__(self, code):
        self.returncode = code


class Recovery(unittest.TestCase):
    def test_requires_signed_one_unit_permit(self):
        p = permit()
        self.assertEqual(verify_permit(p, KEY, "de-node-01", NOW),
                         "mnebyvpn-nodekit-de-node-01-vpn.service")
        for bad in [
            {**p, "mac": "0"*64},
            permit(service="tunnel"),
            permit(action="shell"),
            permit(node="de-node-01;reboot"),
            {**p, "expires_at": (NOW+timedelta(hours=24)).isoformat()},
            {**p, "issued_at": (NOW-timedelta(minutes=8)).isoformat()},
        ]:
            with self.subTest(candidate=str(bad)[:90]), self.assertRaises(ContractError):
                verify_permit(bad, KEY, "de-node-01", NOW)

    def test_disabled_never_runs_command(self):
        p = permit()
        with tempfile.TemporaryDirectory() as d:
            def nope(*args, **kwargs):
                self.fail("disabled runbook must not spawn systemctl")
            with patch("owned_runbook.os.geteuid", return_value=0):
                state = execute(p, KEY, "de-node-01", Path(d)/"ops.sqlite", False,
                                NOW, nope)
            self.assertEqual(state["status"], "disabled")

    def test_only_inactive_owned_service_restart_once(self):
        p = permit()
        with tempfile.TemporaryDirectory() as d:
            calls = []
            def runner(argv, **opts):
                calls.append(argv)
                return Completed(1 if len(calls) == 1 else 0)
            with patch("owned_runbook.os.geteuid", return_value=0):
                r = execute(p, KEY, "de-node-01", Path(d)/"ops.sqlite", True, NOW, runner)
                r2 = execute(p, KEY, "de-node-01", Path(d)/"ops.sqlite", True, NOW, runner)
            self.assertEqual(r["status"], "locally_restarted_pending_external_probe")
            self.assertFalse(r["resolved"])
            self.assertFalse(r["external_e2e_verified"])
            self.assertEqual(r2["status"], "duplicate")
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[1], [
                "/usr/bin/systemctl", "restart", "mnebyvpn-nodekit-de-node-01-vpn.service"
            ])

    def test_active_unit_untouched_and_global_not_executable(self):
        p = permit()
        with tempfile.TemporaryDirectory() as d:
            calls = []
            def runner(argv, **opts):
                calls.append(argv)
                return Completed(0)
            with patch("owned_runbook.os.geteuid", return_value=0):
                result = execute(p, KEY, "de-node-01", Path(d)/"ops.sqlite", True,
                                 NOW, runner)
            self.assertEqual(result["status"], "already_active_no_action")
            self.assertEqual(len(calls), 1)

    def test_restart_failure_escalates_without_repeat(self):
        p = permit()
        with tempfile.TemporaryDirectory() as d:
            calls = []
            def runner(argv, **opts):
                calls.append(argv)
                return Completed(1)
            with patch("owned_runbook.os.geteuid", return_value=0):
                result = execute(p, KEY, "de-node-01", Path(d)/"ops.sqlite", True,
                                 NOW, runner)
            self.assertEqual(result["status"], "restart_failed_escalate")
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
