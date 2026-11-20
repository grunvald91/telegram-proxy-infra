"""Regression for post-cutover RU188 -> restricted PostgreSQL -> FI217 SSH."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fi_awg_postcutover_db_ssh_preflight as preflight


class PostCutoverDbSshTests(unittest.TestCase):
    @staticmethod
    def report(proof="STALE"):
        rows = list(preflight.DB_MARKERS)
        rows.append("FI_AWG_DB_NODE_PROOF=" + proof)
        rows.append("FI_AWG_DB_PROBE=READONLY_READY;PRODUCTION_NODE_PROOF_FRESH=" +
                    ("true" if proof == "FRESH" else "false") +
                    ";WORKER_STARTED=false;CUSTOMER_RELEASE=false")
        return "\n".join(rows) + "\n"

    def test_corrected_db_probe_uses_only_pinned_new_release(self):
        new = preflight.audited_candidate_query()
        self.assertEqual(preflight.NEW_RELEASE, str(preflight.client.RELEASE))
        self.assertNotEqual(preflight.NEW_RELEASE, str(preflight.candidate.CANDIDATE))
        self.assertIn(preflight.NEW_DECLARATION, new)
        self.assertNotIn(preflight.OLD_DECLARATION, new)
        self.assertIn("BEGIN READ ONLY", new)
        self.assertIn("ROLLBACK", new)
        self.assertIn("vpn_awg_clients", new)
        self.assertEqual(new.count(preflight.NEW_DECLARATION), 1)

    def test_live_checker_never_calls_old_five_module_verifier(self):
        from pathlib import Path
        source = (ROOT / "fi_awg_postcutover_db_ssh_preflight.py").read_text()
        self.assertEqual(source.count("clientcut.verify()"), 2)
        self.assertNotIn("cutover.verify()", source)
        self.assertIn("NEW_RELEASE = str(client.RELEASE)", source)

    def test_unknown_legacy_code_change_is_denied(self):
        with mock.patch.object(preflight.legacy, "CODE", "SELECT secret;"):
            with self.assertRaises(preflight.cutover.trust.StageBlocked):
                preflight.audited_candidate_query()

    def test_report_rejects_partial_contradictory_or_forged_success(self):
        for proof in ("STALE", "MISSING", "FRESH"):
            self.assertEqual(preflight.validate_report(self.report(proof)), proof)
        invalid = [
            "",
            self.report("UNKNOWN"),
            self.report("FRESH").replace("RELEASE_DISABLED=PASS",
                                         "RELEASE_DISABLED=FAIL"),
            self.report("STALE").replace("PROOF_FRESH=false","PROOF_FRESH=true"),
            self.report("STALE") + "FI_AWG_DB_CONNECTION=PASS\n",
            self.report("FRESH").replace("ROLE=PASS","ROLE=FAIL"),
            "A" * 1025,
        ]
        for payload in invalid:
            with self.subTest(payload=payload[:40]):
                with self.assertRaises(preflight.cutover.trust.StageBlocked):
                    preflight.validate_report(payload)

    def test_real_runner_is_readonly_and_sanitized(self):
        fake = SimpleNamespace(returncode=0, stdout=self.report("STALE"), stderr="")
        with mock.patch.object(preflight.clientcut, "verify") as cv, \
             mock.patch.object(preflight.node, "trusted_node_binary",
                               return_value=Path("/verified-node")), \
             mock.patch.object(preflight.subprocess, "run", return_value=fake) as run:
            self.assertEqual(preflight.verify_live_db(), "STALE")
            cv.assert_called_once()
            args, kwargs = run.call_args
            self.assertEqual(args[0][:3],
                             ["/verified-node", "--input-type=module", "-e"])
            self.assertIn("BEGIN READ ONLY", args[0][3])
            self.assertEqual(kwargs["stdin"], preflight.subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"],23)

    def test_failing_db_never_contacts_fi(self):
        with mock.patch.object(preflight, "verify_live_db",
                               side_effect=preflight.cutover.trust.StageBlocked("db")), \
             mock.patch.object(preflight.ssh, "probe") as probe:
            with self.assertRaises(preflight.cutover.trust.StageBlocked):
                preflight.main()
            probe.assert_not_called()

    def test_success_requires_fi_forced_ssh_and_two_cutover_checks(self):
        with mock.patch.object(preflight, "verify_live_db", return_value="STALE"), \
             mock.patch.object(preflight.ssh, "probe") as probe, \
             mock.patch.object(preflight.clientcut, "verify") as verified:
            self.assertEqual(preflight.main(),0)
            probe.assert_called_once()
            verified.assert_called_once()

    def test_never_starts_worker_or_enables_customer_release(self):
        source=(ROOT/"fi_awg_postcutover_db_ssh_preflight.py").read_text()
        for forbidden in ("systemctl start","systemctl enable","systemctl restart",
                          "docker exec","UPDATE vpn_release_flags",
                          "INSERT INTO ", "DELETE FROM ","--mode apply"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__=="__main__":
    unittest.main()
