"""Safely stage only pinned production validator bytes while FI AWG is OFF."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

NODEKIT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(NODEKIT))
import fi_awg_production_source_stage as stage

class ProductionSourceTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid()!=0:
            self.skipTest("Run source staging FS tests with sudo (root file ownership)")
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.bundle=self.base/"bundle"
        self.bundle.mkdir(mode=0o700)
        self.app=self.base/"installed"
        self.app.mkdir(mode=0o700)
        self.expected={}
        for name in stage.FILES:
            old=("legacy:"+name).encode()
            new=("approved:"+name).encode()
            self.expected[name]=(new,old)
            self.put(self.bundle/("legacy_"+name),old)
            self.put(self.bundle/name,new)
            self.put(self.app/name,old)
        self.expected[stage.HELPER]=(b"approved:production-policy",None)
        self.put(self.bundle/stage.HELPER,self.expected[stage.HELPER][0])
        self.patches=[
            mock.patch.object(stage,"APP",self.app),
            mock.patch.object(stage,"BACKUPS",self.app/"backup"),
            mock.patch.object(stage,"LOCK",self.app/"source.lock"),
            mock.patch.object(stage,"require_dormant",return_value=None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def put(self,path,payload):
        path.write_bytes(payload)
        path.chmod(0o600)

    def test_first_stage_is_pinned_and_second_stage_is_idempotent(self):
        self.assertEqual(stage.locked_stage(self.bundle,verify_only=True),"LEGACY")
        self.assertFalse(stage.BACKUPS.exists())
        self.assertEqual(stage.locked_stage(self.bundle,verify_only=False),"PINNED_STAGED")
        self.assertEqual(stage.locked_stage(self.bundle,verify_only=False),"PINNED_STAGED")
        self.assertEqual(stage.locked_stage(self.bundle,verify_only=True),"PINNED_STAGED")
        for name,(new,old) in self.expected.items():
            self.assertEqual((stage.APP/name).read_bytes(),new)
            if old is not None:
                self.assertEqual((stage.BACKUPS/(name+".legacy")).read_bytes(),old)

    def test_partial_install_resumes_only_when_proven_backups_exist(self):
        stage.locked_stage(self.bundle,verify_only=False)
        name=stage.FILES[0]
        self.put(stage.APP/name,self.expected[name][1])
        self.assertEqual(stage.status(self.expected),"PARTIAL_PINNED_STAGING")
        self.assertEqual(stage.locked_stage(self.bundle,verify_only=False),"PINNED_STAGED")
        (stage.BACKUPS/(name+".legacy")).unlink()
        with self.assertRaises(stage.Refused):
            stage.locked_stage(self.bundle,verify_only=False)

    def test_preexisting_unapproved_source_never_overwritten(self):
        target=stage.APP/stage.FILES[1]
        self.put(target,b"unapproved code")
        with self.assertRaises(stage.Refused):
            stage.locked_stage(self.bundle,verify_only=False)
        self.assertEqual(target.read_bytes(),b"unapproved code")
        self.assertFalse(stage.BACKUPS.exists())

    def test_policy_helper_drift_and_backup_drift_rejected(self):
        stage.locked_stage(self.bundle,verify_only=False)
        self.put(stage.APP/stage.HELPER,b"foreign helper")
        with self.assertRaises(stage.Refused):
            stage.locked_stage(self.bundle,verify_only=False)
        self.put(stage.APP/stage.HELPER,self.expected[stage.HELPER][0])
        self.put(stage.BACKUPS/(stage.FILES[0]+".legacy"),b"tampered backup")
        with self.assertRaises(stage.Refused):
            stage.locked_stage(self.bundle,verify_only=True)

    def test_concurrent_source_swap_detected(self):
        path=stage.APP/stage.FILES[0]
        with self.assertRaises(stage.Refused):
            stage.replace_atomically(path,b"new content",b"unrelated old")
        self.assertEqual(path.read_bytes(),self.expected[stage.FILES[0]][1])

    def test_untrusted_source_is_rejected(self):
        path=self.bundle/stage.HELPER
        path.chmod(0o644)
        with self.assertRaises(stage.Refused):
            stage.sources(self.bundle)
        path.unlink()
        path.symlink_to("/dev/null")
        with self.assertRaises(stage.Refused):
            stage.sources(self.bundle)

    def test_no_launch_or_firewall_side_effects(self):
        src=(NODEKIT/"fi_awg_production_source_stage.py").read_text()
        for command in ("systemctl start","systemctl enable","systemctl restart",
                        "iptables -I","nft add","sysctl -w",
                        "UPDATE vpn_release_flags","CREATE PEER"):
            self.assertNotIn(command,src)
        self.assertIn("require_dormant()",src)
        self.assertIn("O_NOFOLLOW",src)
        self.assertIn("os.replace",src)

if __name__=="__main__":
    unittest.main()
