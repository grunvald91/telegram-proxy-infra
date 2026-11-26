import unittest
from unittest.mock import patch
import fi_customer_release as a
import fi_external_customer_e2e as e


class ReleaseTest(unittest.TestCase):
    def exercise(self, promote_error=None, gate_closed=True, marker_state='created'):
        with patch.object(e, "verify_ru_database"), patch.object(e, "ssh", side_effect=lambda host,cmd: marker_state if "echo retained" in cmd else "") as ssh, \
             patch.object(e, "denied", return_value=True), \
             patch.object(e, "sql", return_value="true"), \
             patch.object(a, "promote_ru", side_effect=promote_error) as promote, \
             patch.object(a, "gate_closed", return_value=gate_closed):
            if promote_error:
                with self.assertRaises(e.Blocked):
                    a.activate()
            else:
                a.activate()
            promote.assert_called_once()
            return [c.args[1] for c in ssh.call_args_list]

    def test_commit_retains_marker(self):
        cmds = self.exercise()
        self.assertTrue(any("set -C" in c for c in cmds))
        self.assertFalse(any("rm -f" in c for c in cmds))

    def test_resume_retained_marker(self):
        cmds = self.exercise(marker_state="retained")
        self.assertTrue(any("echo retained" in c for c in cmds))
        self.assertFalse(any("rm -f" in c for c in cmds))

    def test_installer_does_not_share_stdin(self):
        from types import SimpleNamespace
        import shlex, subprocess
        with patch.dict(a.os.environ, {"RU_PASSWORD":"test"}), patch.object(a.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="FI_RELEASE_RU=COMMITTED\n",stderr="")) as run:
            a.promote_ru()
        self.assertEqual(run.call_args.kwargs["stdin"],subprocess.DEVNULL)
        self.assertEqual(shlex.split(run.call_args.args[0][-1]),["bash","-c",a.RELEASE.read_text()])
        self.assertNotIn("docker exec -i",a.RELEASE.read_text())

    def test_failed_closed_gate_removes_only_release_marker(self):
        cmds = self.exercise(a.RolledBack("test"), True)
        self.assertTrue(any("rm -f "+e.MARKER in c for c in cmds))

    def test_ambiguous_or_open_gate_retains_marker(self):
        cmds = self.exercise(a.RolledBack("test"), False)
        self.assertFalse(any("rm -f" in c for c in cmds))

    def test_ambiguous_transport_does_not_remove_marker_even_if_gate_currently_closed(self):
        cmds = self.exercise(e.Blocked("transport"), True)
        self.assertFalse(any("rm -f" in c for c in cmds))


if __name__ == "__main__":
    unittest.main()
