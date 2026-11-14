#!/usr/bin/env python3
"""Review regressions for unattended six-host Microsoft DNS state transitions.

All tests are offline: never connect to the real RU database or DE DNS server.
"""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import sys
from unittest import TestCase, main
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/"mnebydns-microsoft-six-permanent-20261111.py"
spec=importlib.util.spec_from_file_location("microsoft_six_review", PATH)
assert spec is not None and spec.loader is not None
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MicrosoftFailureSafety(TestCase):
    def test_probing_after_exception_stops_batch_even_if_checkpoint_clean(self):
        with patch.object(m,"row",return_value={"status":"PROBING"}), \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            with self.assertRaisesRegex(RuntimeError,"UNRESOLVED_OWNER_TRANSITION_PROBING"):
                m.verify_failed_transition("bing.com")

    def test_confirming_after_exception_stops_batch(self):
        with patch.object(m,"row",return_value={"status":"CONFIRMING"}), \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            with self.assertRaisesRegex(RuntimeError,"UNRESOLVED_OWNER_TRANSITION_CONFIRMING"):
                m.verify_failed_transition("xbox.com")

    def test_live_checkpoint_drift_always_aborts_even_after_failure(self):
        with patch.object(m,"row",return_value={"status":"FAILED"}), \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=False):
            with self.assertRaisesRegex(RuntimeError,"SHARED_CHECKPOINT_DRIFT"):
                m.verify_failed_transition("bing.com")

    def test_only_explicit_terminal_failed_or_cancelled_can_continue(self):
        with patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            for state in ("FAILED","CANCELLED","PENDING"):
                with patch.object(m,"row",return_value={"status":state}):
                    self.assertEqual(m.verify_failed_transition("bing.com"),state)

    def test_already_active_but_failing_post_confirmation_health_stops_batch(self):
        with patch.object(m,"row",return_value={"status":"ACTIVE"}), \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            with self.assertRaisesRegex(RuntimeError,"UNVERIFIED_STATE_ACTIVE"):
                m.verify_failed_transition("xbox.com")

    def test_canary_must_be_rolled_back_and_db_rechecked_first(self):
        with patch.object(m,"row",side_effect=[{"status":"CANARY"},{"status":"CANCELLED"}]), \
             patch.object(m,"rollback_live_canary") as rollback, \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            self.assertEqual(m.verify_failed_transition("xbox.com"),"CANCELLED")
        rollback.assert_called_once_with("xbox.com")

    def test_rollback_failure_cannot_be_reported_as_safe(self):
        with patch.object(m,"row",return_value={"status":"CANARY"}), \
             patch.object(m,"rollback_live_canary",side_effect=RuntimeError("UNVERIFIED_ROLLBACK")), \
             patch.object(m.owner,"live_checkpoint_unchanged") as check:
            with self.assertRaisesRegex(RuntimeError,"UNVERIFIED_ROLLBACK"):
                m.verify_failed_transition("xbox.com")
        check.assert_not_called()

    def test_real_main_does_not_process_microsoft_after_bing_stuck_probing(self):
        # The old code appended bing.com|PROBING to the results and attempted
        # microsoft.com even though another owner transition was in flight.
        calls=[]
        def fake_row(domain):
            calls.append(domain)
            if len(calls)==1:return {"status":"APPLY_REQUESTED"}
            return {"status":"PROBING"}
        with patch.object(m,"self_test"), \
             patch.object(m.sys,"argv",["microsoft","run"]), \
             patch.dict(os.environ,{"GITHUB_RUN_ID":"43222220212"}), \
             patch.object(m,"prepare",return_value="REQUESTED") as prepare, \
             patch.object(m,"row",side_effect=fake_row), \
             patch.object(m.owner,"apply",side_effect=RuntimeError("stage failed")), \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            with self.assertRaisesRegex(RuntimeError,"UNRESOLVED_OWNER_TRANSITION_PROBING"):
                m.main()
        prepare.assert_called_once_with(m.TARGETS[0])
        self.assertEqual(set(calls),{m.TARGETS[0]})

    def test_unexpected_apply_result_probing_is_not_a_soft_failure(self):
        seq=[{"status":"APPLY_REQUESTED"},{"status":"PROBING"},{"status":"PROBING"}]
        with patch.object(m,"self_test"), \
             patch.object(m.sys,"argv",["microsoft","run"]), \
             patch.dict(os.environ,{"GITHUB_RUN_ID":"43222220212"}), \
             patch.object(m,"prepare",return_value="REQUESTED") as prepare, \
             patch.object(m,"row",side_effect=seq), \
             patch.object(m.owner,"apply"), \
             patch.object(m.owner,"live_checkpoint_unchanged",return_value=True):
            with self.assertRaisesRegex(RuntimeError,"UNRESOLVED_OWNER_TRANSITION_PROBING"):
                m.main()
        prepare.assert_called_once_with(m.TARGETS[0])


if __name__=="__main__":
    main()
