"""Offline contract for pinned RU188 AWG device-enrollment queue staging."""
from pathlib import Path
import re
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_device_queue_stage as stage

class FiAwgDeviceQueueStageTests(unittest.TestCase):
    def test_reviewed_mnebyvpn_commit_and_git_blob_pinned(self):
        self.assertRegex(stage.COMMIT,r"^[a-f0-9]{40}$")
        self.assertRegex(stage.BLOB,r"^[a-f0-9]{40}$")
        self.assertEqual(stage.FILENAME,"0136_awg_device_enrollment_queue.sql")
        self.assertTrue(stage.STAGE.fullmatch("/run/fi-awg-device-queue.aBcD1234"))
        self.assertFalse(stage.STAGE.fullmatch("/tmp/fi-awg-device-queue.aBcD1234"))
        self.assertFalse(stage.STAGE.fullmatch("/run/fi-awg-device-queue.x/../../etc"))

    def test_no_activation_and_exact_database_preflight(self):
        code=(ROOT/"fi_awg_device_queue_stage.py").read_text()
        for required in (
            "trust.preflight()","trust.trusted_parent(directory)",
            "trust.private_file(directory/FILENAME,10000)",
            "hashlib.sha1(", "trust.role_exists()",
            "vpn_awg_clients","fi_device_queue_release_must_remain_off",
            "trust.verify_privileges()",
            "has_function_privilege('mnebyvpn_site_auth'",
            "has_table_privilege('mnebyvpn_awg_delivery'",
            "CUSTOMER_RELEASE=false","REAL_PEERS_MODIFIED=false",
        ):
            with self.subTest(required=required):
                self.assertIn(required,code)
        self.assertNotIn("systemctl start",code)
        self.assertNotIn("UPDATE vpn_release_flags SET enabled=true",code)
        self.assertNotIn("INSERT INTO vpn_awg_peer_allocations",code)

    def test_gh_actions_only_live_on_main_after_tests_with_pinned_ssh(self):
        y=(ROOT.parent/".github/workflows/fi-awg-device-queue-stage.yml").read_text()
        for required in (
            "  pull_request:","    branches: [main]",
            "    needs: offline","github.event_name != 'pull_request'",
            "StrictHostKeyChecking yes","HostKeyAlgorithms ssh-ed25519",
            "mnebydns-owner-ssh-known_hosts",
            "80abe4e7adc26f452d06974f6b5eb0bcbe46c922",
            "fi_awg_device_queue_stage.py","--stage",
            "FI_AWG_DEVICE_QUEUE=VERIFIED",
            "WORKER_ACTIVE=false;CUSTOMER_RELEASE=false",
        ):
            with self.subTest(required=required):
                self.assertIn(required,y)
        self.assertNotIn("StrictHostKeyChecking accept-new",y)
        self.assertNotIn("systemctl start",y)

if __name__=="__main__":
    unittest.main()
