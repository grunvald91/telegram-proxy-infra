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
        def fail_once(files):
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
