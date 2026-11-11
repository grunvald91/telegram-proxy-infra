#!/usr/bin/env python3
"""Offline fail-closed tests for owner DNS confirmation and recovery paths."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "mnebydns-owner-domain-controller-20261110.py"
spec = importlib.util.spec_from_file_location("owner_domain_controller", SCRIPT)
assert spec is not None and spec.loader is not None
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def confirm_row(status="CONFIRMING"):
    return {
        "id": "101", "revision": "2", "run": "42808637895",
        "domain": "oracle.com", "expires": "9999999999",
        "status": status, "updated": "0",
    }


class OwnerDomainConfirmContracts(TestCase):
    def test_recovered_checkpoint_requires_live_proof_before_active(self):
        statements = []
        with patch.object(owner, "is_confirmed", return_value=True), \
             patch.object(owner, "verified_live_confirmed", side_effect=RuntimeError("stale")), \
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            with self.assertRaisesRegex(RuntimeError, "stale"):
                owner.confirm(confirm_row())
        self.assertFalse(any("status='ACTIVE'" in q for q in statements))

    def test_recovered_checkpoint_passes_health_before_active(self):
        statements = []
        order = []
        with patch.object(owner, "is_confirmed", return_value=True), \
             patch.object(owner, "verified_live_confirmed", side_effect=lambda _: order.append("checkpoint")), \
             patch.object(owner, "oracle_canary_check", side_effect=lambda *_: order.append("dns")), \
             patch.object(owner, "tls_public_route", side_effect=lambda _: order.append("tls")), \
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            owner.confirm(confirm_row())
        self.assertEqual(order, ["checkpoint", "dns", "tls"])
        self.assertTrue(any("status='ACTIVE'" in q and "status='CONFIRMING'" in q for q in statements))

    def test_interrupted_removal_that_committed_does_not_rollback(self):
        statements = []
        row = confirm_row("REMOVING")
        with patch.object(owner, "is_confirmed", return_value=True), \
             patch.object(owner, "rollback", side_effect=AssertionError("must not rollback")), \
             patch.object(owner, "verified_live_confirmed"), \
             patch.object(owner, "oracle_canary_check"), \
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            owner.remove(row)
        self.assertTrue(any("status='CANCELLED'" in q and "status='REMOVING'" in q for q in statements))

    def test_recovered_removal_fails_closed_on_unverified_live_state(self):
        statements = []
        with patch.object(owner, "is_confirmed", return_value=True), \
             patch.object(owner, "verified_live_confirmed", side_effect=RuntimeError("drift")), \
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            with self.assertRaisesRegex(RuntimeError, "drift"):
                owner.remove(confirm_row("REMOVING"))
        self.assertFalse(any("status='CANCELLED'" in q for q in statements))

    def test_uncommitted_removal_rolls_back_before_cancelling(self):
        statements = []
        with patch.object(owner, "is_confirmed", return_value=False), \
             patch.object(owner, "rollback") as rollback, \
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            owner.remove(confirm_row("REMOVING"))
        rollback.assert_called_once_with("42808637895")
        self.assertFalse(any("status='CANCELLED'" in q for q in statements))

    def test_expired_canary_has_priority_over_queued_add(self):
        # A pending new domain must not indefinitely hide an expired canary.
        with patch.object(owner, "sql", return_value="") as db:
            self.assertIsNone(owner.get_task())
        query = db.call_args.args[0]
        expired = query.index("WHEN status='CANARY' AND canary_expires_at<=now() THEN 0")
        add = query.index("WHEN status='APPLY_REQUESTED' THEN 6")
        self.assertLess(expired, add)

    def test_confirmation_recovery_command_checks_both_pilot_files(self):
        with patch.object(owner, "ssh", return_value="true") as remote:
            self.assertTrue(owner.is_confirmed("42808637895"))
        command = remote.call_args.args[1]
        self.assertIn("sha256sum -c stable-manifest.sha256", command)
        self.assertIn('cmp -s "$root/dns.stable" "$base/dns.pilot"', command)
        self.assertIn('cmp -s "$root/nginx.stable" "$base/nginx.pilot"', command)
        self.assertIn('bash "$base/confirm.sh" "$base"', command)


class OwnerDomainInterruptedStageContracts(TestCase):
    def test_missing_rollback_script_is_safe_only_when_live_baseline_is_unchanged(self):
        with patch.object(owner, "rollback", side_effect=RuntimeError("missing")), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=True):
            owner.rollback_or_unchanged("42808637895")

    def test_missing_rollback_script_with_live_drift_is_not_accepted(self):
        with patch.object(owner, "rollback", side_effect=RuntimeError("missing")), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNVERIFIED"):
                owner.rollback_or_unchanged("42808637895")

    def test_stale_probing_task_recovers_if_stage_never_changed_server(self):
        task = confirm_row("PROBING")
        with patch.object(owner, "get_task", return_value=task), \
             patch.object(owner, "rollback", side_effect=RuntimeError("missing")), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=True), \
             patch.object(owner, "update_error") as error, \
             patch.object(owner.sys, "argv", ["controller", "run"]):
            owner.main()
        error.assert_called_once_with(task, "INTERRUPTED_OWNER_DEPLOY")

    def test_stale_probing_with_live_drift_does_not_mark_failed(self):
        task = confirm_row("PROBING")
        with patch.object(owner, "get_task", return_value=task), \
             patch.object(owner, "rollback", side_effect=RuntimeError("missing")), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=False), \
             patch.object(owner, "update_error") as error, \
             patch.object(owner.sys, "argv", ["controller", "run"]):
            with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNVERIFIED"):
                owner.main()
        error.assert_not_called()


class OwnerDomainLiveHealthAndSSH(TestCase):
    def test_ssh_strictly_pins_host_key_even_with_password(self):
        self.assertTrue(owner.PINNED_SSH_HOSTS.exists())
        with patch.object(owner, "cmd", return_value="OK") as runner, \
             patch.dict(owner.os.environ, {"DE_PASS": "testing-only"}):
            self.assertEqual(owner.ssh("de", "true"), "OK")
        args=runner.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519", args)
        self.assertIn("UserKnownHostsFile="+str(owner.PINNED_SSH_HOSTS), args)
        self.assertNotIn("StrictHostKeyChecking=accept-new", args)

    def test_active_health_green_keeps_exact_pinned_ip_and_clears_only_own_error(self):
        statements=[]
        def query(q):
            statements.append(q)
            if q.startswith("SELECT"):return "18|www.python.org|93.184.215.14|5"
            return ""
        with patch.object(owner, "sql", side_effect=query), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=True), \
             patch.object(owner, "ssh", side_effect=lambda role, cmd, timeout=90:
                          "ACTIVE_PINNED_ROUTE_VERIFIED" if "set -Eeuo" in cmd else "ACTIVE_PINNED_ORIGIN_TLS_OK"), \
             patch.object(owner, "oracle_canary_check") as dns, \
             patch.object(owner, "tls_public_route") as tls:
            owner.active_health()
        self.assertEqual(dns.call_args.args, ("www.python.org", True))
        tls.assert_called_once_with("www.python.org")
        self.assertTrue(any("last_error_code=NULL" in q and
                            "last_error_code='ACTIVE_ROUTE_CHECK_FAILED'" in q for q in statements))
        self.assertFalse(any("status='CANCELLED'" in q or "status='FAILED'" in q for q in statements))

    def test_active_health_failure_is_reported_without_dns_mutation(self):
        statements=[]
        def query(q):
            statements.append(q)
            if q.startswith("SELECT"):return "18|www.python.org|93.184.215.14|5"
            return ""
        with patch.object(owner, "sql", side_effect=query), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=True), \
             patch.object(owner, "ssh", side_effect=RuntimeError("origin down")), \
             patch.object(owner, "rollback", side_effect=AssertionError("must not rollback")), \
             patch.object(owner, "oracle_canary_check", side_effect=AssertionError("must not run")), \
             patch.object(owner, "tls_public_route", side_effect=AssertionError("must not run")):
            owner.active_health()
        self.assertTrue(any("last_error_code='ACTIVE_ROUTE_CHECK_FAILED'" in q for q in statements))
        self.assertFalse(any("status='FAILED'" in q or "status='CANCELLED'" in q for q in statements))

    def test_active_health_drift_must_not_overwrite_failure_status(self):
        with patch.object(owner, "live_checkpoint_unchanged", return_value=False), \
             patch.object(owner, "sql") as queries:
            owner.active_health()
        queries.assert_not_called()

    def test_active_monitor_runs_with_nonempty_domain_queue(self):
        task = confirm_row("CANARY")
        with patch.object(owner, "get_task", return_value=task), \
             patch.object(owner, "active_health") as health, \
             patch.object(owner, "cancel_canary", side_effect=AssertionError("must not cancel")), \
             patch.object(owner.time, "time", return_value=100), \
             patch.object(owner.sys, "argv", ["controller", "run"]):
            owner.main()
        health.assert_called_once()

    def test_active_monitor_still_runs_when_owner_transition_fails(self):
        task = confirm_row("ROLLBACK_REQUESTED")
        with patch.object(owner, "get_task", return_value=task), \
             patch.object(owner, "cancel_canary", side_effect=RuntimeError("transition-failed")), \
             patch.object(owner, "active_health") as health, \
             patch.object(owner.sys, "argv", ["controller", "run"]):
            with self.assertRaisesRegex(RuntimeError, "transition-failed"):
                owner.main()
        health.assert_called_once()

    def test_active_monitor_failure_does_not_mask_transition_failure(self):
        task = confirm_row("ROLLBACK_REQUESTED")
        with patch.object(owner, "get_task", return_value=task), \
             patch.object(owner, "cancel_canary", side_effect=RuntimeError("owner-state-failed")), \
             patch.object(owner, "active_health", side_effect=RuntimeError("monitor-failed")), \
             patch.object(owner.sys, "argv", ["controller", "run"]):
            with self.assertRaisesRegex(RuntimeError, "owner-state-failed"):
                owner.main()

    def test_main_idle_work_cycle_invokes_active_monitor(self):
        with patch.object(owner, "get_task", return_value=None), \
             patch.object(owner, "active_health") as health, \
             patch.object(owner.sys, "argv", ["controller", "run"]):
            owner.main()
        health.assert_called_once()



class OwnerDomainPsqlResultParsing(TestCase):
    def test_production_sql_uses_quiet_tuple_output_for_cas_returning_id(self):
        with patch.object(owner, "ssh", return_value="42") as remote:
            self.assertEqual(owner.sql("UPDATE dns_admin_domains SET revision=revision+1 RETURNING id"), "42")
        command=remote.call_args.args[1]
        self.assertIn("psql -XqAt -v ON_ERROR_STOP=1", command)
        self.assertNotIn("psql -v ON_ERROR_STOP=1 -At", command)

    def test_claim_can_progress_after_psql_command_tag_fix(self):
        row={"id":"42","revision":"2","domain":"www.rfc-editor.org",
             "status":"APPLY_REQUESTED","run":"","updated":"0","expires":""}
        queries=[]
        def query(statement):
            queries.append(statement)
            if "count(*)" in statement:return "0"
            if "RETURNING id" in statement:return "42"
            return ""
        with patch.object(owner, "RUNID", "428400112231"), \
             patch.object(owner, "sql", side_effect=query), \
             patch.object(owner, "live_checkpoint_unchanged", return_value=True), \
             patch.object(owner, "transfer_to_de", side_effect=RuntimeError("stop after claim")), \
             patch.object(owner, "rollback_or_unchanged"), \
             patch.object(owner, "update_error"):
            with self.assertRaisesRegex(RuntimeError, "stop after claim"):
                owner.apply(row)
        self.assertTrue(any("status='PROBING'" in q and "RETURNING id" in q for q in queries))


class OwnerDNSRestartReadiness(TestCase):
    def test_dot_tcp_refusal_is_retried_before_tls_query(self):
        with patch.object(owner.socket, "create_connection",
                          side_effect=[ConnectionRefusedError(111, "test"),
                                       object()]) as network, \
             patch.object(owner.time, "sleep") as wait:
            tcp=owner.connect_dot()
        self.assertIsNotNone(tcp)
        self.assertEqual(network.call_count, 2)
        wait.assert_called_once()
        self.assertEqual(wait.call_args.args[0], 0.3)

    def test_dot_tcp_refusal_is_bounded_and_never_claims_success(self):
        with patch.object(owner.socket, "create_connection",
                          side_effect=ConnectionRefusedError(111,"test")) as network, \
             patch.object(owner.time, "sleep") as wait:
            with self.assertRaisesRegex(RuntimeError,"DOMAIN_DOT_RESTART_NOT_READY"):
                owner.connect_dot()
        self.assertEqual(network.call_count, 7)
        self.assertEqual(wait.call_count, 6)

    def test_untrusted_tls_or_network_error_is_not_silently_ignored(self):
        with patch.object(owner.socket, "create_connection",
                          side_effect=OSError("untrusted network")), \
             patch.object(owner.time,"sleep") as wait:
            with self.assertRaisesRegex(OSError,"untrusted network"):
                owner.connect_dot()
        wait.assert_not_called()

    def test_removal_and_rollback_require_public_dot_listener_after_restart(self):
        removal=(ROOT/"mnebydns-owner-domain-remove-20261110.sh").read_text()
        rollback=(ROOT/"mnebydns-owner-domain-rollback-20261110.sh").read_text()
        for script in (removal, rollback):
            self.assertIn("ss -H -lnt 'sport = :853'",script)
            self.assertIn("89.125.90.101:853",script)
            self.assertIn("systemctl is-active --quiet mnebydns-dot.service",script)
            self.assertIn("sleep .2",script)


if __name__ == "__main__":
    main()
