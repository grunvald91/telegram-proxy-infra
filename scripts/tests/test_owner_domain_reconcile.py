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
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            owner.remove(row)
        self.assertTrue(any("status='CANCELLED'" in q and "status='REMOVING'" in q for q in statements))

    def test_uncommitted_removal_rolls_back_before_cancelling(self):
        statements = []
        with patch.object(owner, "is_confirmed", return_value=False), \
             patch.object(owner, "rollback") as rollback, \
             patch.object(owner, "sql", side_effect=lambda q: statements.append(q) or "101"):
            owner.remove(confirm_row("REMOVING"))
        rollback.assert_called_once_with("42808637895")
        self.assertFalse(any("status='CANCELLED'" in q for q in statements))

    def test_confirmation_recovery_command_checks_both_pilot_files(self):
        with patch.object(owner, "ssh", return_value="true") as remote:
            self.assertTrue(owner.is_confirmed("42808637895"))
        command = remote.call_args.args[1]
        self.assertIn("sha256sum -c stable-manifest.sha256", command)
        self.assertIn("cmp -s \\"$root/dns.stable\\" \\"$base/dns.pilot\\"", command)
        self.assertIn("cmp -s \\"$root/nginx.stable\\" \\"$base/nginx.pilot\\"", command)
        self.assertIn('bash "$base/confirm.sh" "$base"', command)


if __name__ == "__main__":
    main()
