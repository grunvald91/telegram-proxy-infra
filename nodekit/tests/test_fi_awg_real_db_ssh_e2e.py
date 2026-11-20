"""Offline contract tests for real but disposable RU188 -> FI217 AWG E2E."""
from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_e2e_disposable_postgres as pg
import fi_awg_e2e_fi_guard as fi


class RealDisposableE2ETests(unittest.TestCase):
    def test_postgres_launch_is_ephemeral_loopback_and_pinned_image(self):
        source=(ROOT/"fi_awg_e2e_disposable_postgres.py").read_text()
        self.assertEqual(pg.PORT,55434)
        self.assertNotEqual(pg.CONTAINER,"mnebyvpn-stage-postgres")
        self.assertIn('"--pull=never"',source)
        self.assertIn('"--network=bridge"',source)
        self.assertIn('f"127.0.0.1:{PORT}:5432"',source)
        self.assertIn('docker("rm","-f",CONTAINER',source)
        self.assertNotIn('"docker","exec","mnebyvpn-stage-postgres"',source)

    def test_stage_path_cannot_escape_run(self):
        self.assertTrue(pg.STAGING.fullmatch("/run/fi-awg-real-e2e.aBcD1234"))
        for unsafe in ("/tmp/fi-awg-real-e2e.aBcD1234",
                       "/run/fi-awg-real-e2e.aBcD1234/extra",
                       "/run/fi-awg-real-e2e.",
                       "/run/fi-awg-real-e2e.1234;rm"):
            self.assertFalse(pg.STAGING.fullmatch(unsafe))

    def test_migrations_must_be_reviewed_sql_files(self):
        self.assertTrue(pg.ALLOWED.fullmatch("0135_awg_worker_row_lock_gateway.sql"))
        self.assertFalse(pg.ALLOWED.fullmatch("../../../etc/passwd"))
        self.assertFalse(pg.ALLOWED.fullmatch("install.sh"))

    def test_fi_arm_kill_timer_before_start_and_fail_closed(self):
        s=(ROOT/"fi_awg_e2e_fi_guard.py").read_text()
        self.assertLess(s.index('"--on-active=95s"'),s.index('["/usr/bin/systemctl","start",live.UNIT]'))
        self.assertIn("live.preflight(bundle)",s)
        self.assertIn("live.install_watchdog()",s)
        self.assertIn("live.safe_cleanup(grant)",s)
        self.assertIn("db_e2e_cleanup_non_synthetic_ledger",s)
        self.assertNotIn("vpn_release_flags",s)

    def test_reject_cleanup_when_other_peers_present(self):
        fixture={
            "grant":{"entitlementId":"00000000-0000-4000-8000-000000000001",
                     "peerPublicKey":"s"*44,"clientIpv4":"10.73.91.254"},
            "revoke":{"op":"revoke"}
        }
        with mock.patch.object(fi.signed,"is_host",return_value=True), \
             mock.patch.object(fi.signed,"protected",
                return_value=json.dumps(fixture).encode()), \
             mock.patch.object(fi.live,"residual_ledger_status",
                return_value="UNVERIFIED"), \
             mock.patch.object(fi.live,"safe_cleanup") as cleanup:
            with self.assertRaises(fi.live.CanaryBlocked):
                fi.cleanup(Path("/run/disposable-fi-test"))
            cleanup.assert_not_called()

    def test_node_e2e_checks_actual_pinned_ru_signer_and_signed_db_ack(self):
        js=(ROOT/"fi_awg_real_db_ssh_e2e.mjs").read_text()
        for required in (
            "trustedControllerKey(", "deliverNextAwgCommand(",
            "stageAwgRevoke(", "node_receipt_sha256",
            "FI_AWG_E2E=REAL_FI_SIGNED_GRANT_ACK_PERSISTED",
            "FI_AWG_E2E=REAL_FI_SIGNED_REVOKE_ACK_PERSISTED",
            "fi_awg_e2e", "127\\.0\\.0\\.1:55434",
            "createPublicKey(controller)", "fi-node-public.spki",
        ):
            with self.subTest(required=required):
                self.assertIn(required,js)
        self.assertNotIn("spawnSync=()=>",js)
        self.assertNotIn("runner=(",js)

    def test_action_never_merges_or_starts_customers(self):
        y=(ROOT.parent/".github/workflows/fi-awg-real-db-ssh-e2e.yml").read_text()
        for required in ("--mode prepare","--mode cleanup",
                         "--mode stop", "db_attempted=false",
                         "fi_attempted=false","REAL_FI_PEER=true",
                         "CUSTOMER_RELEASE=false","node-fi"):
            self.assertIn(required,y)
        self.assertNotIn("systemctl start mnebyvpn-awg-delivery.service",y)
        self.assertNotIn("UPDATE public.vpn_release_flags",y)


if __name__=="__main__":
    unittest.main()
