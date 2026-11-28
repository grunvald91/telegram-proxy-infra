import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_public_dot_recover as m
class RecoveryTests(unittest.TestCase):
    def test_already_active_does_not_restart(self):
        with patch.object(m,"preflight"),patch.object(m,"active",return_value=True),patch.object(m,"listeners",return_value=[m.FI+":853"]),patch.object(m,"probe") as probe,patch.object(m,"run") as run:
            self.assertEqual(m.restore(),"already_active")
            run.assert_not_called()
            self.assertEqual(probe.call_count,2)
    def test_preflight_failure_never_starts(self):
        with patch.object(m,"preflight",side_effect=m.Blocked("dependency_inactive")),patch.object(m,"run") as run:
            with self.assertRaises(m.Blocked):m.restore()
            run.assert_not_called()
    def test_failed_public_probe_rolls_back_only_dot(self):
        with patch.object(m,"preflight"),patch.object(m,"active",side_effect=[False,False,True]),patch.object(m,"listeners",side_effect=[[],[m.FI+":853"],[]]),patch.object(m,"probe",side_effect=m.Blocked("unknown_credential_accepted")),patch.object(m,"run") as run:
            with self.assertRaises(m.Blocked):m.restore()
            self.assertEqual(run.call_args_list[-1].args,("systemctl","stop",m.SOCKET,m.SERVICE))
    def test_conflicting_listener_never_started(self):
        with patch.object(m,"preflight"),patch.object(m,"active",return_value=False),patch.object(m,"listeners",return_value=["0.0.0.0:853"]),patch.object(m,"run") as run:
            with self.assertRaises(m.Blocked):m.restore()
            run.assert_not_called()
if __name__=="__main__":unittest.main()
