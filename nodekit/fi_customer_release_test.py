import unittest
from unittest.mock import patch
import fi_customer_release as a
import fi_external_customer_e2e as e


class ReleaseTest(unittest.TestCase):
    def exercise(self, promote_error=None, gate_closed=True):
        with patch.object(e, "verify_ru_database"), patch.object(e, "ssh") as ssh, \
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
