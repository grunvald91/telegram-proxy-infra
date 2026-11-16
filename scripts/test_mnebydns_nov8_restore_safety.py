#!/usr/bin/env python3
"""Offline-only regressions for MNEBYDNS 8 Nov restore safety."""
from datetime import datetime,timedelta,timezone
from pathlib import Path
import os
import tempfile
import unittest
from mnebydns_nov8_restore_safety import (
    capture,digest,atomic_replace,route_lock,conditional_rollback,
    persistent_watchdog,commit_marker,original_template_parity)

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.path=self.root/"Corefile"
        self.path.write_bytes(b"before\n")
        self.path.chmod(0o640)
        self.orig=capture(self.path)

    def test_atomic_write_preserves_owner_group_mode_and_data(self):
        result=atomic_replace(self.path,self.orig,b"after\n")
        self.assertEqual(result.sha256,digest(b"after\n"))
        self.assertEqual(result.uid,self.orig.uid)
        self.assertEqual(result.gid,self.orig.gid)
        self.assertEqual(result.mode,0o640)
        self.assertEqual(result.xattrs,self.orig.xattrs)

    def test_reject_changed_bytes_without_mutation(self):
        self.path.write_bytes(b"somebody changed DNS\n")
        with self.assertRaises(RuntimeError):
            atomic_replace(self.path,self.orig,b"unsafe\n")
        self.assertEqual(self.path.read_bytes(),b"somebody changed DNS\n")

    def test_reject_changed_mode_without_mutation(self):
        self.path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            atomic_replace(self.path,self.orig,b"unsafe\n")
        self.assertEqual(self.path.read_bytes(),b"before\n")

    def test_reject_symlink(self):
        fake=self.root/"link"
        fake.symlink_to(self.path)
        with self.assertRaises(ValueError):capture(fake)

    def test_conditional_rollback_restores_only_own_stage(self):
        stage=atomic_replace(self.path,self.orig,b"staged\n")
        actions=conditional_rollback({"dns":(self.path,self.orig,stage,b"before\n")})
        self.assertEqual(actions,{"dns":"restore"})
        self.assertEqual(capture(self.path),self.orig)

    def test_refuse_any_rollback_if_other_file_changed(self):
        second=self.root/"nginx.conf"
        second.write_bytes(b"one\n")
        old_nginx=capture(second)
        stage_nginx=atomic_replace(second,old_nginx,b"two\n")
        stage_dns=atomic_replace(self.path,self.orig,b"stage dns\n")
        second.write_bytes(b"external edit\n")
        with self.assertRaises(RuntimeError):
            conditional_rollback({
                "dns":(self.path,self.orig,stage_dns,b"before\n"),
                "nginx":(second,old_nginx,stage_nginx,b"one\n")})
        self.assertEqual(self.path.read_bytes(),b"stage dns\n")
        self.assertEqual(second.read_bytes(),b"external edit\n")

    def test_no_partial_backup_with_bad_digest(self):
        stage=atomic_replace(self.path,self.orig,b"staged\n")
        with self.assertRaises(RuntimeError):
            conditional_rollback({"dns":(self.path,self.orig,stage,b"wrong backup")})
        self.assertEqual(self.path.read_bytes(),b"staged\n")

    def test_watchdog_persistent_calendar_survives_reboot(self):
        when=datetime.now(timezone.utc)+timedelta(minutes=10)
        service,timer=persistent_watchdog("mnebydns-google-nov8-recover",when,
                                         "/usr/bin/python3 /opt/mnebydns/recover.py --rollback")
        self.assertIn("Type=oneshot",service)
        self.assertIn("OnCalendar=",timer)
        self.assertIn("Persistent=true",timer)
        self.assertIn("Unit=mnebydns-google-nov8-recover.service",timer)

    def test_watchdog_rejects_exec_injection(self):
        when=datetime.now(timezone.utc)+timedelta(minutes=10)
        for bad in ("/usr/bin/python3 /tmp/recover.py; rm -rf /",
                    "/usr/bin/python3 /tmp/recover.py\nExecStart=/bin/false"):
            with self.assertRaises(ValueError):
                persistent_watchdog("mnebydns-google-recover",when,bad)

    def test_commit_marker_immutable(self):
        commit_marker(self.root,{"dns":"x"})
        self.assertTrue((self.root/"COMMITTED").is_file())
        with self.assertRaises(FileExistsError):
            commit_marker(self.root,{"dns":"y"})

    def test_historical_templates_compare_rr_types(self):
        core="""tls://.:853 {
    template IN A www.youtube.com {
        match ^www[.]youtube[.]com[.]$
        answer "{{ .Name }} 20 IN A 89.125.90.101"
        fallthrough
    }
    template IN AAAA www.youtube.com {
        match ^www[.]youtube[.]com[.]$
        rcode NOERROR
        fallthrough
    }
    template IN HTTPS www.youtube.com {
        match ^www[.]youtube[.]com[.]$
        rcode NOERROR
        fallthrough
    }
}"""
        self.assertTrue(original_template_parity(core,core)["all_historical_rules_retained"])
        changed=core.replace("template IN AAAA","template IN CNAME")
        report=original_template_parity(core,changed)
        self.assertFalse(report["all_historical_rules_retained"])
        self.assertEqual(report["missing_or_changed_historical"],1)

    def test_empty_original_google_policy_must_fail(self):
        with self.assertRaises(ValueError):
            original_template_parity("not a CoreDNS config", "still not CoreDNS")

    def test_route_lock_excludes_concurrent_open(self):
        lock=self.root/"route.lock"
        with route_lock(lock):
            with self.assertRaises(BlockingIOError):
                with route_lock(lock):pass

if __name__=="__main__":
    unittest.main()
