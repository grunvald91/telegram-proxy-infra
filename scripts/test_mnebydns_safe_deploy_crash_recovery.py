#!/usr/bin/env python3
"""Offline crash/reboot-window recovery simulation using a fresh interpreter.

No server reboot, systemd mutation, DNS requests, SSH, or production files.
The two stages are separate OS processes and share only checkpoint files.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

from mnebydns_nov8_restore_safety import atomic_replace, capture, digest
from mnebydns_safe_deploy import state_obj


class CrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.txroot=self.root/"tx"
        self.txroot.mkdir()
        self.tx=self.txroot/"abcdef0123456789"
        self.tx.mkdir()
        self.live=self.root/"Corefile"
        self.live.write_bytes(b"original production DNS config\n")
        self.live.chmod(0o640)
        self.baseline=capture(self.live)
        old=self.live.read_bytes()
        new=b"candidate production DNS config\n"
        record={"version":1,"id":self.tx.name,
                "files":{"dns":{
                    "before":state_obj(self.baseline),
                    "staged":state_obj(self.baseline).__or__({"sha256":digest(new)})
                }}}
        (self.tx/"dns.before").write_bytes(old)
        (self.tx/"state.json").write_text(json.dumps(record))
        self.candidate=new

    def recover_in_new_process(self):
        script=StringRecovery
        result=subprocess.run([sys.executable,"-c",script,str(self.root),str(self.tx)],
             text=True,capture_output=True,timeout=12,
             env={**os.environ,"PYTHONPATH":str(Path(__file__).resolve().parent)})
        if result.returncode:
            self.fail("Recovery in fresh process failed: "+result.stderr[-1100:])
        return json.loads(result.stdout.strip())

    def test_interrupted_install_recovers_original_bytes(self):
        atomic_replace(self.live,self.baseline,self.candidate)
        result=self.recover_in_new_process()
        self.assertTrue(result["rolled_back"])
        self.assertEqual(self.live.read_bytes(),b"original production DNS config\n")
        self.assertEqual(capture(self.live),self.baseline)
        self.assertTrue((self.tx/"ROLLED_BACK").is_file())

    def test_interruption_before_swap_is_noop_recovery(self):
        result=self.recover_in_new_process()
        self.assertTrue(result["rolled_back"])
        self.assertEqual(self.live.read_bytes(),b"original production DNS config\n")

    def test_durable_commit_survives_process_restart(self):
        atomic_replace(self.live,self.baseline,self.candidate)
        (self.tx/"COMMITTED").write_text("committed\n")
        result=self.recover_in_new_process()
        self.assertTrue(result["committed"])
        self.assertEqual(self.live.read_bytes(),self.candidate)
        self.assertFalse((self.tx/"ROLLED_BACK").exists())

    def test_intervening_change_is_not_overwritten(self):
        atomic_replace(self.live,self.baseline,self.candidate)
        self.live.write_bytes(b"somebody else edited DNS\n")
        result=subprocess.run([sys.executable,"-c",StringRecovery,
            str(self.root),str(self.tx)],text=True,capture_output=True,
            timeout=12,env={**os.environ,"PYTHONPATH":str(Path(__file__).resolve().parent)})
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.live.read_bytes(),b"somebody else edited DNS\n")
        self.assertFalse((self.tx/"ROLLED_BACK").exists())


StringRecovery = r'''
import json,sys
from pathlib import Path
from unittest.mock import patch
import mnebydns_safe_deploy as deploy
import mnebydns_nov8_restore_safety as safety
root=Path(sys.argv[1])
tx=Path(sys.argv[2])
deploy.TXROOT=root/"tx"
deploy.LIVE={"dns":root/"Corefile"}
with patch.object(deploy,"verify_system",return_value=None),\
     patch.object(deploy,"revert_services",return_value=None),\
     patch.object(deploy,"ensure_dns_reader_access",return_value=None),\
     patch.object(deploy,"smoke_check",return_value=None),\
     patch.object(deploy,"require_services_healthy",return_value=None),\
     patch.object(deploy,"route_lock",side_effect=lambda:safety.route_lock(root/"route.lock")):
    deploy.recover(tx)
'''


if __name__=="__main__":
    unittest.main()
