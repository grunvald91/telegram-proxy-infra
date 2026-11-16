#!/usr/bin/env python3
"""Offline tests for installable guarded MNEBYDNS production deploy CLI.

No SSH, DNS packets, systemctl calls or production file writes.
"""
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch, MagicMock
import hashlib
import json
import tempfile

import mnebydns_safe_deploy as deploy
import mnebydns_nov8_restore_safety as safety

REAL_MANIFEST_FOR=deploy.manifest_for


class DeployTests(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.stage=self.root/"stage"
        self.stage.mkdir(mode=0o700)
        self.tx=self.root/"tx"
        self.tx.mkdir(mode=0o700)
        self.live=self.root/"Corefile"
        self.live.write_bytes(b"old policy\n")
        self.live.chmod(0o640)
        self.key="google-restore"
        self.stage_dir=self.stage/self.key
        self.stage_dir.mkdir(mode=0o700)
        self.candidate=self.stage_dir/"dns.new"
        self.candidate.write_bytes(b"new policy\n")
        self.expected=safety.digest(self.live.read_bytes())
        self.target=safety.digest(self.candidate.read_bytes())
        self.manifest={"dns":{"expected_sha256":self.expected,
                               "candidate_sha256":self.target}}
        patches=(
            patch.object(deploy,"INSTALL",self.root),
            patch.object(deploy,"TXROOT",self.tx),
            patch.object(deploy,"STAGE",self.stage),
            patch.object(deploy,"LIVE",{"dns":self.live}),
            patch.object(deploy,"verify_system",return_value=None),
            patch.object(deploy,"ensure_dns_reader_access",return_value=None),
            patch.object(deploy,"validate_owner_checkpoint",return_value=None),
            patch.object(deploy,"validate_owner_candidate",return_value=None),
            patch.object(deploy,"preserved",return_value={"preserved":True}),
            patch.object(deploy,"ensure_hot_reload_config",return_value=None),
            patch.object(deploy,"smoke_check",return_value={"all_pinned":True}),
            patch.object(deploy,"coredns_pid",return_value="23456"),
            patch.object(deploy,"manifest_for",return_value=self.manifest),
            patch.object(deploy,"require_services_healthy",
                         return_value={"dns":{"service_active":True,"tcp_listener":True}}),
            patch.object(deploy,"route_lock",side_effect=lambda:safety.route_lock(self.root/"lock")),
            patch.object(deploy,"systemd_files",return_value="mnebydns-safe-recover-offline"),
            patch.object(deploy,"cmd",return_value=""),
            patch.object(deploy,"revert_services",return_value=None),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_successful_transaction_preserves_group_and_creates_commit(self):
        before=safety.capture(self.live)
        deploy.apply(self.key)
        after=safety.capture(self.live)
        self.assertEqual(after.sha256,self.target)
        self.assertTrue(safety.same_metadata(before,after))
        found=list(self.tx.iterdir())
        self.assertEqual(len(found),1)
        self.assertTrue((found[0]/"COMMITTED").is_file())
        self.assertEqual((found[0]/"dns.before").read_bytes(),b"old policy\n")

    def test_noop_does_not_touch_live_or_create_transaction(self):
        self.candidate.write_bytes(self.live.read_bytes())
        self.manifest["dns"]["candidate_sha256"]=self.expected
        deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")
        self.assertEqual(list(self.tx.iterdir()),[])

    def test_stage_sha_mismatch_aborts_without_mutation(self):
        self.candidate.write_bytes(b"unreviewed changes\n")
        with self.assertRaises(RuntimeError):
            deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")
        self.assertEqual(list(self.tx.iterdir()),[])

    def test_live_hash_mismatch_aborts_without_mutation(self):
        self.live.write_bytes(b"concurrent edit\n")
        with self.assertRaises(RuntimeError):
            deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"concurrent edit\n")
        self.assertEqual(list(self.tx.iterdir()),[])

    def test_activation_failure_rolls_back_owned_bytes(self):
        counts={"n":0}
        def fail_once(files,**kwargs):
            counts["n"]+=1
            if counts["n"]==1:
                raise RuntimeError("simulated service startup failure")
        with patch.object(deploy,"revert_services",side_effect=fail_once):
            with self.assertRaises(RuntimeError):
                deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")
        found=list(self.tx.iterdir())
        self.assertEqual(len(found),1)
        self.assertTrue((found[0]/"ROLLED_BACK").is_file())

    def test_external_intervention_blocks_rollback(self):
        deploy.apply(self.key)
        found=list(self.tx.iterdir())[0]
        (found/"COMMITTED").unlink()
        self.live.write_bytes(b"independent subsequent update\n")
        with self.assertRaises(RuntimeError):
            deploy.recover_locked(found)
        self.assertEqual(self.live.read_bytes(),b"independent subsequent update\n")

    def test_committed_transaction_can_never_rollback(self):
        deploy.apply(self.key)
        found=list(self.tx.iterdir())[0]
        result=deploy.recover_locked(found)
        self.assertTrue(result["committed"])
        self.assertFalse(result["rolled_back"])
        self.assertEqual(self.live.read_bytes(),b"new policy\n")

    def test_recovery_without_live_changes_never_restarts_dns(self):
        deploy.apply(self.key)
        tx=list(self.tx.iterdir())[0]
        (tx/"COMMITTED").unlink()
        self.live.write_bytes(b"old policy\n")
        with patch.object(deploy,"revert_services") as reload_mock:
            result=deploy.recover_locked(tx)
            self.assertTrue(result["rolled_back"])
            reload_mock.assert_not_called()

    def test_missing_dns_reader_group_fails_before_writes(self):
        with patch.object(deploy,"ensure_dns_reader_access",side_effect=RuntimeError("no access")):
            with self.assertRaises(RuntimeError):
                deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")
        self.assertEqual(list(self.tx.iterdir()),[])

    def test_committed_timer_disable_failure_is_not_false_rollback(self):
        def failed_disarm(*args,**kwargs):
            if "disable" in args:raise RuntimeError("systemd failure")
            return ""
        with patch.object(deploy,"cmd",side_effect=failed_disarm):
            deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"new policy\n")
        tx=list(self.tx.iterdir())[0]
        self.assertTrue((tx/"COMMITTED").exists())
        self.assertFalse((tx/"ROLLED_BACK").exists())

    def test_non_disruptive_hot_reload_never_calls_restart(self):
        with patch.object(deploy,"coredns_pid",return_value="12345"), \
             patch.object(deploy,"ensure_hot_reload_config") as check, \
             patch.object(deploy,"time") as timer, \
             patch.object(deploy,"require_services_healthy") as healthy:
            deploy.hot_reload_dns()
            check.assert_called_once()
            timer.sleep.assert_called_once_with(7)
            healthy.assert_called_once_with({"dns"})

    def test_pre_publish_pid_change_triggers_rollback(self):
        # Model an external service restart occurring between preflight
        # and the end of the atomic file swap.
        counts={"n":0}
        def pid():
            counts["n"]+=1
            return "23456" if counts["n"]==1 else "23457"
        with patch.object(deploy,"coredns_pid",side_effect=pid):
            with self.assertRaisesRegex(RuntimeError,"PID changed"):
                deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")
        tx=list(self.tx.iterdir())[0]
        self.assertTrue((tx/"ROLLED_BACK").is_file())
        self.assertFalse((tx/"COMMITTED").exists())

    def test_pre_publish_pid_is_forwarded_to_hot_reload_verification(self):
        # Ensure the actual original resolver PID is passed to the
        # post-replace hot-reload path, not sampled only after replace.
        with patch.object(deploy,"revert_services") as reload:
            deploy.apply(self.key)
            reload.assert_any_call({"dns": reload.call_args.args[0]["dns"]},
                                   dns_expected_pid="23456")

    def test_hot_reload_rejects_restart_before_check(self):
        with patch.object(deploy,"coredns_pid",return_value="34567"):
            with self.assertRaisesRegex(RuntimeError,"restarted before"):
                deploy.hot_reload_dns(expected_pid="23456")

    def test_owner_domain_stage_and_rollback_preserve_metadata(self):
        self.ownerroot=self.root/"owner"
        self.ownerroot.mkdir(mode=0o700)
        base=self.ownerroot/"123456789"
        base.mkdir(mode=0o700)
        (base/"domain").write_text("oracle.com")
        (base/"dns.before").write_bytes(b"old policy\n")
        (base/"dns.pilot").write_bytes(b"owner policy\n")
        with patch.object(deploy,"OWNERROOT",self.ownerroot):
            deploy.owner_publish("stage",base,"dns")
            self.assertEqual(self.live.read_bytes(),b"owner policy\n")
            self.assertEqual(safety.capture(self.live).mode,0o640)
            deploy.owner_publish("rollback",base,"dns")
            self.assertEqual(self.live.read_bytes(),b"old policy\n")

    def test_owner_domain_rejects_external_edit_before_rollback(self):
        root=self.root/"owner"
        root.mkdir(mode=0o700)
        base=root/"123456789"
        base.mkdir(mode=0o700)
        (base/"domain").write_text("oracle.com")
        (base/"dns.before").write_bytes(b"old policy\n")
        (base/"dns.pilot").write_bytes(b"owner policy\n")
        with patch.object(deploy,"OWNERROOT",root):
            deploy.owner_publish("stage",base,"dns")
            self.live.write_bytes(b"unrelated third-party change\n")
            with self.assertRaises(RuntimeError):
                deploy.owner_publish("rollback",base,"dns")
            self.assertEqual(self.live.read_bytes(),b"unrelated third-party change\n")

    def test_source_candidate_without_reader_group_does_not_publish(self):
        with patch.object(deploy,"ensure_hot_reload_config",side_effect=RuntimeError("no reload")):
            with self.assertRaises(RuntimeError):deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")

    def test_invalid_manifest_path_does_not_escape_stage(self):
        with self.assertRaises(ValueError):
            REAL_MANIFEST_FOR("../outside")

    def test_candidate_symlink_is_rejected(self):
        self.candidate.unlink()
        other=self.root/"elsewhere"
        other.write_bytes(b"new policy\n")
        self.candidate.symlink_to(other)
        with self.assertRaises(RuntimeError):
            deploy.apply(self.key)
        self.assertEqual(self.live.read_bytes(),b"old policy\n")


if __name__=="__main__":
    main()
