#!/usr/bin/env python3
"""Offline integration tests: production DNS and systemd are never contacted."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import mnebydns_nov8_safe_release as release
from mnebydns_nov8_restore_safety import capture,digest,atomic_replace

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.live=self.root/"live"
        self.live.mkdir()
        self.root_checkpoint=self.root/"installed"/"checkpoints"
        self.root_checkpoint.mkdir(parents=True)
        self.files={k:self.live/("mnebydns-"+k+".conf") for k in release.FILES}
        for k,p in self.files.items():
            p.write_bytes(("old-"+k+"\n").encode())
            p.chmod(0o640 if k=="dns" else 0o600)
        self.service_stub=patch.object(release,"FILES",self.files)
        self.service_stub.start()
        self.addCleanup(self.service_stub.stop)
        self.checkpoint_stub=patch.object(release,"CHECKPOINTS",self.root_checkpoint)
        self.checkpoint_stub.start()
        self.addCleanup(self.checkpoint_stub.stop)
        self.lock_stub=patch.object(release,"route_lock",lambda: self.lock())
        self.lock_stub.start()
        self.addCleanup(self.lock_stub.stop)
        self.group_stub=patch.object(release,"assert_dns_reader",lambda:None)
        self.group_stub.start()
        self.addCleanup(self.group_stub.stop)
        self.ready_stub=patch.object(release,"wait_ready",lambda *a,**kw:None)
        self.ready_stub.start()
        self.addCleanup(self.ready_stub.stop)
        self.euid_stub=patch.object(release.os,"geteuid",lambda:0)
        self.euid_stub.start()
        self.addCleanup(self.euid_stub.stop)
        self.timer_stub=patch.object(release,"installed_watchdog",lambda *a,**kw:"mnebydns-test-unit")
        self.timer_stub.start()
        self.addCleanup(self.timer_stub.stop)
        self.systemd_stub=patch.object(release,"run",lambda *a,**kw:"active")
        self.systemd_stub.start()
        self.addCleanup(self.systemd_stub.stop)
        self.reload_stub=patch.object(release,"reload_services",lambda *a,**kw:None)
        self.reload_stub.start()
        self.addCleanup(self.reload_stub.stop)
    def lock(self):
        from mnebydns_nov8_restore_safety import route_lock
        return route_lock(self.root/"guard.lock")
    def prepare(self,release_id="google-nov8-fix",patches=None):
        folder=self.root/("stage-"+release_id)
        folder.mkdir()
        expected={k:digest(p.read_bytes()) for k,p in self.files.items()}
        new=patches if patches is not None else {"dns":b"new-dns\n"}
        m={"schema":1,"id":release_id,"expected":expected,
           "new":{k:digest(v) for k,v in new.items()}}
        (folder/"release.json").write_text(json.dumps(m))
        for k,blob in new.items():
            (folder/(k+".new")).write_bytes(blob)
        return folder
    def test_noop_does_not_create_checkpoint_or_replace_files(self):
        folder=self.prepare(patches={"dns":self.files["dns"].read_bytes()})
        release.apply(folder)
        self.assertEqual(list(self.root_checkpoint.iterdir()),[])
        self.assertEqual(self.files["dns"].read_bytes(),b"old-dns\n")
    def test_apply_atomically_preserves_metadata_and_commits(self):
        old=capture(self.files["dns"])
        folder=self.prepare()
        release.apply(folder)
        self.assertEqual(self.files["dns"].read_bytes(),b"new-dns\n")
        after=capture(self.files["dns"])
        self.assertEqual((after.uid,after.gid,after.mode,after.xattrs),
                         (old.uid,old.gid,old.mode,old.xattrs))
        self.assertTrue((self.root_checkpoint/"google-nov8-fix"/"COMMITTED").is_file())
        self.assertEqual(self.files["pilot"].read_bytes(),b"old-pilot\n")
        self.assertEqual(self.files["shared"].read_bytes(),b"old-shared\n")
    def test_rollback_uncommitted_release(self):
        folder=self.prepare()
        m, staged=release.validate_stage(folder)
        with self.lock():
            states={k:capture(v) for k,v in self.files.items()}
            release.stage_manifest(m,states,staged,self.root_checkpoint/m["id"])
            atomic_replace(self.files["dns"],states["dns"],staged["dns"])
        release.rollback(m["id"])
        self.assertEqual(self.files["dns"].read_bytes(),b"old-dns\n")
        self.assertTrue((self.root_checkpoint/m["id"]/"ROLLED_BACK").is_file())
    def test_refuse_rollback_over_third_party(self):
        folder=self.prepare()
        m,staged=release.validate_stage(folder)
        with self.lock():
            states={k:capture(v) for k,v in self.files.items()}
            release.stage_manifest(m,states,staged,self.root_checkpoint/m["id"])
            atomic_replace(self.files["dns"],states["dns"],staged["dns"])
        self.files["dns"].write_bytes(b"third party edit\n")
        with self.assertRaises(RuntimeError):
            release.rollback(m["id"])
        self.assertEqual(self.files["dns"].read_bytes(),b"third party edit\n")
    def test_production_drift_aborts_before_checkpoint(self):
        folder=self.prepare()
        self.files["pilot"].write_bytes(b"external pilot change\n")
        with self.assertRaises(RuntimeError):
            release.apply(folder)
        self.assertEqual(list(self.root_checkpoint.iterdir()),[])
        self.assertEqual(self.files["dns"].read_bytes(),b"old-dns\n")
    def test_wrong_manifest_stage_sha_aborts(self):
        folder=self.prepare()
        (folder/"dns.new").write_bytes(b"unapproved change\n")
        with self.assertRaises(ValueError):
            release.apply(folder)
        self.assertEqual(list(self.root_checkpoint.iterdir()),[])
    def test_too_long_id_fails(self):
        folder=self.prepare(release_id="google-"+"z"*45)
        with self.assertRaises(ValueError):
            release.apply(folder)
    def test_no_symlink_stage(self):
        folder=self.prepare()
        (folder/"dns.new").unlink()
        (folder/"dns.new").symlink_to(self.files["dns"])
        with self.assertRaises(ValueError):
            release.apply(folder)
    def test_rollback_committed_release_does_not_touch_content(self):
        folder=self.prepare()
        release.apply(folder)
        release.rollback("google-nov8-fix")
        self.assertEqual(self.files["dns"].read_bytes(),b"new-dns\n")
    def test_failed_reload_stages_persistent_rollback_and_attempts_recovery(self):
        folder=self.prepare()
        calls={"n":0}
        def fail_once(keys):
            calls["n"]+=1
            if calls["n"]==1:raise RuntimeError("test hot reload fail")
        with patch.object(release,"reload_services",fail_once):
            with self.assertRaises(RuntimeError):
                release.apply(folder)
        self.assertEqual(self.files["dns"].read_bytes(),b"old-dns\n")
        self.assertFalse((self.root_checkpoint/"google-nov8-fix"/"COMMITTED").exists())
        self.assertEqual(calls["n"],2)

if __name__=="__main__":
    unittest.main()
