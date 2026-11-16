#!/usr/bin/env python3
"""Offline tests for owner-domain atomic swap; no server interaction."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import mnebydns_safe_owner_swap as swap
from mnebydns_nov8_restore_safety import capture

class OwnerSwapTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.base_root=root/"owner"
        self.base_root.mkdir()
        self.base=self.base_root/"1234567890"
        self.base.mkdir()
        self.target=root/"Corefile"
        self.target.write_bytes(b"old core\n")
        self.target.chmod(0o640)
        (self.base/"dns.before").write_bytes(b"old core\n")
        (self.base/"dns.pilot").write_bytes(b"new core\n")
        self.lock=root/"route.lock"
        self.lock.touch()
        # The parent shell owns fd 9. In unit tests use the equivalent inode.
        for obj,field,value in ((swap,"ALLOW",{"dns":self.target}),
                                (swap,"CHECKPOINT",self.base_root),
                                (swap,"LOCK",self.lock)):
            p=patch.object(obj,field,value)
            p.start()
            self.addCleanup(p.stop)
        f=patch.object(swap.os,"fstat",lambda fd:self.lock.stat() if fd==9 else None)
        f.start()
        self.addCleanup(f.stop)
        uid=patch.object(swap.os,"geteuid",return_value=0)
        uid.start()
        self.addCleanup(uid.stop)
    def test_stage_and_rollback_preserve_metadata(self):
        original=capture(self.target)
        swap.safe_swap("dns",str(self.base),"dns.before","dns.pilot")
        self.assertEqual(self.target.read_bytes(),b"new core\n")
        self.assertEqual(capture(self.target).mode,original.mode)
        self.assertEqual(capture(self.target).gid,original.gid)
        swap.safe_swap("dns",str(self.base),"dns.pilot","dns.before")
        self.assertEqual(self.target.read_bytes(),b"old core\n")
    def test_rejects_concurrent_edit(self):
        self.target.write_bytes(b"changed by someone else\n")
        with self.assertRaises(RuntimeError):
            swap.safe_swap("dns",str(self.base),"dns.before","dns.pilot")
        self.assertEqual(self.target.read_bytes(),b"changed by someone else\n")
    def test_rejects_wrong_file_scope(self):
        with self.assertRaises(ValueError):
            swap.safe_swap("dns",str(self.base),"nginx.before","nginx.pilot")
    def test_rejects_bad_stage(self):
        with self.assertRaises(RuntimeError):
            swap.safe_swap("dns",str(self.base_root/"not-a-checkpoint"),"dns.before","dns.pilot")
    def test_rejects_symlink_pilot(self):
        (self.base/"dns.pilot").unlink()
        (self.base/"dns.pilot").symlink_to(self.target)
        with self.assertRaises(RuntimeError):
            swap.safe_swap("dns",str(self.base),"dns.before","dns.pilot")
    def test_missing_shared_lock_refused(self):
        with patch.object(swap.os,"fstat",side_effect=OSError("bad fd")):
            with self.assertRaises(OSError):
                swap.safe_swap("dns",str(self.base),"dns.before","dns.pilot")

if __name__=="__main__":
    unittest.main()
