#!/usr/bin/env python3
"""Offline safety/transition tests for MNEBYDNS unattended 108-domain canaries."""
from __future__ import annotations
import importlib.util
import os
import shlex
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch, call

SRC=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("mnebydns_108_batch",SRC/"mnebydns-batch-108-canary-20261112.py")
assert SPEC is not None and SPEC.loader is not None
batch=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(batch)

class Batch108Inventory(TestCase):
    def test_exact_attested_108_and_excluded_existing_hosts(self):
        names=batch.inventory()
        self.assertEqual(len(names),108)
        self.assertEqual(len(set(names)),108)
        self.assertTrue({"chatgpt.com","grok.com","sentry.io"}.isdisjoint(names))

    def test_git_switch_requires_explicit_value(self):
        self.assertIsInstance(batch.enabled(),bool)

    def test_push_can_activate_only_when_switch_is_enabled(self):
        self.assertTrue(batch.deploy_event_allowed("push",True))
        self.assertFalse(batch.deploy_event_allowed("push",False))
        self.assertTrue(batch.deploy_event_allowed("schedule",True))
        self.assertFalse(batch.deploy_event_allowed("schedule",False))
        self.assertTrue(batch.deploy_event_allowed("workflow_dispatch",False))
        self.assertFalse(batch.deploy_event_allowed("pull_request",True))

    def test_canary_ids_are_per_hostname_and_bounded(self):
        with patch.dict(os.environ,{"GITHUB_RUN_ID":"43186450621"}):
            ids=[batch.phase_id(i) for i in range(1,6)]
        self.assertEqual(len(set(ids)),5)
        for value in ids:self.assertTrue(9<=len(value)<=13)
        with patch.dict(os.environ,{"GITHUB_RUN_ID":"43186450621"}):
            for illegal in (0,6,-1):
                with self.assertRaises(ValueError):
                    batch.phase_id(illegal)

    def test_pg_inet_metadata_accepts_host_prefix_only(self):
        self.assertEqual(batch.owner.pg_inet_host("13.227.192.109/32"),
                         "13.227.192.109")
        self.assertEqual(batch.owner.pg_inet_host("13.227.192.109"),
                         "13.227.192.109")
        for bad in ("13.227.192.109/24","10.0.0.1/32","::1/128",
                    "13.227.192.109/abc","89.125.90.101/32",""):
            with self.assertRaises(ValueError,msg=bad):
                batch.owner.pg_inet_host(bad)

    def test_select_pending_skips_active_and_failed(self):
        names=("a.example.com","b.example.com","c.example.com")
        rows={
           "a.example.com":("ACTIVE",batch.PRODUCT,""),
           "b.example.com":("FAILED",batch.PRODUCT,"BATCH_PREFLIGHT_UNVERIFIED"),
           "c.example.com":("PENDING",batch.PRODUCT,"")
        }
        self.assertEqual(batch.select_next(names,rows),"c.example.com")
        rows["c.example.com"]=("ACTIVE",batch.PRODUCT,"")
        self.assertIsNone(batch.select_next(names,rows))

    def test_other_owner_pending_is_skipped_without_overwrite(self):
        rows={"a.example.com":("PENDING","Custom domain",""),
              "b.example.com":("PENDING",batch.PRODUCT,"")}
        self.assertEqual(batch.select_next(("a.example.com","b.example.com"),rows),
                         "b.example.com")
        self.assertIsNone(batch.select_next(("a.example.com",),rows))
        rows["a.example.com"]=("ACTIVE","Custom domain","")
        self.assertIsNone(batch.select_next(("a.example.com",),rows))

    def test_incident_stops_future_waves(self):
        with self.assertRaisesRegex(RuntimeError,"BATCH_CIRCUIT_BREAKER"):
            batch.preexisting_failure({"a.example.com":("FAILED",batch.PRODUCT,
                                     "BATCH_INCIDENT_CANARY_ABORT")},["a.example.com"])
        batch.preexisting_failure({"a.example.com":("FAILED",batch.PRODUCT,
                                 "BATCH_PREFLIGHT_UNVERIFIED")},["a.example.com"])

    def test_busy_queue_checked_before_live_mutation(self):
        with patch.object(batch,"db",return_value="1"),patch.object(batch.owner,"live_checkpoint_unchanged"):
            with self.assertRaisesRegex(RuntimeError,"OWNER_QUEUE_BUSY"):
                batch.ensure_quiet()

    def test_remote_python_payloads_compile_before_live_use(self):
        compile(batch.HTTP_CODE,"<remote_http>", "exec")
        with patch.object(batch.owner,"ssh",return_value="93.184.215.14") as remote, \
             patch.object(batch,"http_probe",side_effect=[200,403]):
            batch.preflight("a.example.com")
        command=remote.call_args.args[1]
        parts=shlex.split(command)
        self.assertEqual(parts[0:2],["python3","-c"])
        compile(parts[2],"<remote_dns_and_tls>","exec")

    def test_preflight_requires_fresh_same_ip_ru403_foreign2xx(self):
        with patch.object(batch.owner,"ssh",return_value="93.184.215.14"), \
             patch.object(batch,"http_probe",side_effect=[200,403]) as probe:
            addr,de,ru=batch.preflight("a.example.com")
        self.assertEqual((addr,de,ru),("93.184.215.14",200,403))
        self.assertEqual(probe.call_args_list,[
            call("de","a.example.com","93.184.215.14"),
            call("ru","a.example.com","93.184.215.14")])
        with patch.object(batch.owner,"ssh",return_value="93.184.215.14"), \
             patch.object(batch,"http_probe",side_effect=[200,200]):
            with self.assertRaisesRegex(RuntimeError,"STALE_DIFFERENTIAL"):
                batch.preflight("a.example.com")

class Batch108Transactions(TestCase):
    def test_compare_and_swap_can_only_change_owned_pending_record(self):
        with patch.object(batch,"db",return_value="a.example.com") as sql:
            batch.cas("a.example.com","PENDING","APPLY_REQUESTED")
        query=sql.call_args.args[0]
        self.assertIn("WHERE domain='a.example.com' AND product='Research 2026-11'",query)
        self.assertIn("status='PENDING' RETURNING domain",query)
        self.assertIn("revision=revision+1",query)
        with patch.object(batch,"db",return_value="") as sql:
            with self.assertRaisesRegex(RuntimeError,"compare-and-swap"):
                batch.cas("a.example.com","PENDING","APPLY_REQUESTED")

    def test_successful_route_uses_controller_and_http_before_confirmation(self):
        domain="a.example.com"
        tasks=[{"domain":domain,"status":"APPLY_REQUESTED"},
               {"domain":domain,"status":"CONFIRM_REQUESTED"}]
        status=["CANARY","ACTIVE"]
        with patch.object(batch,"ensure_quiet"),patch.object(batch,"capacity"), \
             patch.object(batch,"set_phase",return_value="431864506211"), \
             patch.object(batch,"preflight",return_value=("93.184.215.14",200,403)), \
             patch.object(batch.owner,"live_checkpoint_unchanged",return_value=True), \
             patch.object(batch,"cas") as sql, \
             patch.object(batch,"select_own_task",side_effect=tasks), \
             patch.object(batch.owner,"apply") as apply, \
             patch.object(batch.owner,"confirm") as confirm, \
             patch.object(batch,"status_of",side_effect=status), \
             patch.object(batch,"db",return_value="93.184.215.14/32"), \
             patch.object(batch,"http_probe",side_effect=[200,403,302]) as http, \
             patch.object(batch.owner,"oracle_canary_check") as oracle, \
             patch.object(batch,"report"):
            self.assertTrue(batch.run_one(domain,1))
        self.assertEqual(sql.call_count,2)
        self.assertEqual(sql.call_args_list[0].args[:3],
                         (domain,"PENDING","APPLY_REQUESTED"))
        self.assertEqual(sql.call_args_list[1].args[:3],
                         (domain,"CANARY","CONFIRM_REQUESTED"))
        apply.assert_called_once()
        confirm.assert_called_once()
        self.assertEqual(http.call_args_list,[
            call("de",domain,"93.184.215.14"),
            call("ru",domain,"93.184.215.14"),
            call("ru",domain,batch.owner.EDGE)])
        oracle.assert_called_once_with(domain,True)

    def test_rotating_cdn_ip_is_not_rejected_when_actual_pin_revalidates(self):
        domain="a.example.com"
        previous="93.184.215.14"
        rotated="13.227.192.109"
        tasks=[{"domain":domain,"status":"APPLY_REQUESTED"},
               {"domain":domain,"status":"CONFIRM_REQUESTED"}]
        with patch.object(batch,"ensure_quiet"),patch.object(batch,"capacity"), \
             patch.object(batch,"set_phase"), \
             patch.object(batch,"preflight",return_value=(previous,200,403)), \
             patch.object(batch.owner,"live_checkpoint_unchanged",return_value=True), \
             patch.object(batch,"cas"), \
             patch.object(batch,"select_own_task",side_effect=tasks), \
             patch.object(batch.owner,"apply"), \
             patch.object(batch.owner,"confirm") as confirmed, \
             patch.object(batch,"status_of",side_effect=["CANARY","ACTIVE"]), \
             patch.object(batch,"db",return_value=rotated+"/32"), \
             patch.object(batch,"http_probe",side_effect=[200,403,200]) as http, \
             patch.object(batch.owner,"oracle_canary_check"), \
             patch.object(batch,"report") as report:
            self.assertTrue(batch.run_one(domain,1))
        self.assertEqual(http.call_args_list,[
            call("de",domain,rotated),call("ru",domain,rotated),
            call("ru",domain,batch.owner.EDGE)])
        self.assertTrue(any(x.args[0]=="CDN_ORIGIN_ROTATED_REVALIDATED"
                            for x in report.call_args_list))
        confirmed.assert_called_once()

    def test_incorrect_ru_public_http_skips_only_candidate_after_safe_rollback(self):
        domain="a.example.com"
        with patch.object(batch,"ensure_quiet"),patch.object(batch,"capacity"), \
             patch.object(batch,"set_phase",return_value="431864506211"), \
             patch.object(batch,"preflight",return_value=("93.184.215.14",200,403)), \
             patch.object(batch.owner,"live_checkpoint_unchanged",return_value=True), \
             patch.object(batch,"cas") as sql, \
             patch.object(batch,"select_own_task",return_value={"domain":domain,"status":"APPLY_REQUESTED"}), \
             patch.object(batch.owner,"apply"), \
             patch.object(batch.owner,"confirm") as confirm, \
             patch.object(batch,"status_of",side_effect=["CANARY","CANARY","CANARY"]), \
             patch.object(batch,"db",side_effect=["93.184.215.14/32",domain]) as db, \
             patch.object(batch,"http_probe",side_effect=[200,403,403]), \
             patch.object(batch.owner,"rollback_or_unchanged") as rollback, \
             patch.object(batch.owner,"oracle_canary_check") as oracle, \
             patch.object(batch,"report"):
            batch.owner.RUNID="431864506211"
            self.assertFalse(batch.run_one(domain,1))
        rollback.assert_called_once_with("431864506211")
        oracle.assert_called_once_with(domain,False)
        confirm.assert_not_called()
        self.assertEqual(sql.call_count,1)
        self.assertIn("last_error_code='BATCH_CANDIDATE_HTTPS_FAILED'",db.call_args.args[0])

    def test_transient_preflight_does_not_mark_domain_failed(self):
        with patch.object(batch,"ensure_quiet"),patch.object(batch,"capacity"), \
             patch.object(batch,"set_phase"), \
             patch.object(batch,"preflight",side_effect=RuntimeError("SSH_NETWORK_DOWN")), \
             patch.object(batch,"cas") as cas,patch.object(batch,"report"):
            with self.assertRaisesRegex(RuntimeError,"SSH_NETWORK_DOWN"):
                batch.run_one("a.example.com",1)
        cas.assert_not_called()

    def test_confirmed_stale_preflight_is_recorded_without_live_route(self):
        with patch.object(batch,"ensure_quiet"),patch.object(batch,"capacity"), \
             patch.object(batch,"set_phase"), \
             patch.object(batch,"preflight",side_effect=RuntimeError("STALE_DIFFERENTIAL")), \
             patch.object(batch,"cas") as cas,patch.object(batch,"report"):
            self.assertFalse(batch.run_one("a.example.com",1))
        cas.assert_called_once_with("a.example.com","PENDING","FAILED",
                                    "last_error_code='BATCH_PREFLIGHT_UNVERIFIED'")

    def test_system_regression_still_fails_closed_and_sets_incident_marker(self):
        domain="a.example.com"
        with patch.object(batch,"ensure_quiet"),patch.object(batch,"capacity"), \
             patch.object(batch,"set_phase",return_value="431864506211"), \
             patch.object(batch,"preflight",return_value=("93.184.215.14",200,403)), \
             patch.object(batch.owner,"live_checkpoint_unchanged",return_value=True), \
             patch.object(batch,"cas"), \
             patch.object(batch,"select_own_task",return_value={"domain":domain,"status":"APPLY_REQUESTED"}), \
             patch.object(batch.owner,"apply"), \
             patch.object(batch,"status_of",side_effect=["CANARY","CANARY","CANARY"]), \
             patch.object(batch,"db",side_effect=["93.184.215.14/32",domain]) as db, \
             patch.object(batch,"http_probe",side_effect=[200,403,200]), \
             patch.object(batch.owner,"oracle_canary_check",side_effect=[RuntimeError("stable dot broken"),None]), \
             patch.object(batch.owner,"rollback_or_unchanged") as rollback, \
             patch.object(batch,"report"):
            batch.owner.RUNID="431864506211"
            with self.assertRaisesRegex(RuntimeError,"stable dot broken"):
                batch.run_one(domain,1)
        rollback.assert_called_once_with("431864506211")
        self.assertIn("last_error_code='BATCH_INCIDENT_CANARY_ABORT'",db.call_args.args[0])

    def test_uncertain_confirm_state_cannot_be_called_rolled_back(self):
        with patch.object(batch,"status_of",return_value="CONFIRMING"), \
             patch.object(batch.owner,"rollback_or_unchanged") as rollback, \
             patch.object(batch,"report"):
            with self.assertRaisesRegex(RuntimeError,"CONFIRM_STATE_UNCERTAIN"):
                batch.recover_failed_canary("a.example.com","431864506211")
        rollback.assert_not_called()

    def test_successful_preflight_only_marks_bad_candidate_failed(self):
        with patch.object(batch,"cas") as cas,patch.object(batch,"report"):
            batch.fail_preflight("a.example.com","STALE_DIFFERENTIAL")
        cas.assert_called_once_with("a.example.com","PENDING","FAILED",
                                    "last_error_code='BATCH_PREFLIGHT_UNVERIFIED'")

if __name__=="__main__":
    main()
