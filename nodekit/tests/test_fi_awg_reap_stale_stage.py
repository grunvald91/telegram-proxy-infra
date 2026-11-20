"""Static and pure-function tests for strict, emergency FI stage SIGTERM."""
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_reap_stale_stage as repair


class StaleStageTests(unittest.TestCase):
    def test_only_exact_python_staging_command(self):
        stage="/run/fi-awg-client-worker.AbCd1234"
        self.assertTrue(repair.exact_stage_argv(
            ("python3",stage+"/fi_awg_client_worker_stage.py",
             "--stage",stage)))
        self.assertTrue(repair.exact_stage_argv(
            ("/usr/bin/python3",stage+"/fi_awg_client_worker_stage.py",
             "--stage",stage)))
        wrong=(
            ("python3",stage+"/fi_awg_client_worker_stage.py","--stage",
             "/run/fi-awg-client-worker.Other123"),
            ("python3",stage+"/fi_awg_worker_delivery.py","--stage",stage),
            ("python3",stage+"/fi_awg_client_worker_stage.py","--stage","/tmp"),
            ("python3",stage+"/fi_awg_client_worker_stage.py","--delete",stage),
            ("bash",stage+"/fi_awg_client_worker_stage.py","--stage",stage),
            ("python3","/root/something.py","--stage",stage),
            ("python3",stage+"/fi_awg_client_worker_stage.py","--stage",
             stage,"--force"),
        )
        for argv in wrong:
            with self.subTest(argv=argv):
                self.assertFalse(repair.exact_stage_argv(argv))

    def test_repair_only_two_stale_userowned_stage_processes(self):
        source=(ROOT/"fi_awg_reap_stale_stage.py").read_text()
        for required in (
            "REQUIRED_STAGE_COUNT = 2", "MIN_AGE_SECONDS = 300",
            "os.geteuid() == 0", "not APPROVAL.exists()",
            "systemctl", "is-active", "is-enabled",
            "WorkingDirectory", "OLD_RELEASE",
            "vpn_awg_clients","state == \"false\"",
            "new_release_already_published",
            "stat.S_IMODE(info.st_mode) != 0o600",
            "stat.S_ISREG", "info.st_nlink != 1",
            "os.O_NOFOLLOW", "fcntl.LOCK_NB",
            "stage_process_changed_before_repair",
            "stage_pid_reused", "signal.SIGTERM",
            "source_lock_not_freed", "CLIENT_RELEASE=false",
            "CUSTOMER_PEERS_TOUCHED=false",
        ):
            with self.subTest(required=required):
                self.assertIn(required,source)
        for prohibited in (
            "SIGKILL", "os.killpg", "pkill", "killall", "systemctl start",
            "systemctl restart", "docker rm", "docker stop",
            "UPDATE public.vpn_release_flags SET enabled=true",
            "wget", "curl", "http.client",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited,source)

    def test_never_shadows_existing_live_process_commands(self):
        self.assertEqual(repair.UNIT,"mnebyvpn-awg-delivery.service")
        self.assertEqual(repair.LOCK.name,"awg-worker-source-stage.lock")
        self.assertNotEqual(repair.OLD_RELEASE,repair.NEW_RELEASE)
        self.assertFalse(repair.exact_stage_argv(
            ("python3","/opt/mnebyvpn-controller/awg-worker-releases/"
             "446c331249085adb6536e3d9913fb4b68abf6cd7/"
             "apps/service/src/awg-controller-delivery-worker.ts","--stage","/run/foo")))
        self.assertFalse(repair.exact_stage_argv(
            ("python3","/run/fi-awg-client-worker.12345678/"
             "fi_awg_client_worker_stage.py","--stage","/run/elsewhere"))


if __name__=="__main__":
    unittest.main()
