import unittest
from unittest import mock
import subprocess
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_recover_existing as m

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.g=mock.Mock()
        self.e=mock.Mock()
        self.patches=[
            mock.patch.object(m,"preflight",return_value=(self.g,self.e)),
            mock.patch.object(m,"states",return_value=("failed","inactive","inactive")),
            mock.patch.object(m,"IFACE"),
            mock.patch.object(m,"verify_egress"),
            mock.patch.object(m,"verify_live"),
            mock.patch.object(m,"verify_peers"),
            mock.patch.object(m,"call"),
            mock.patch.object(m,"systemd",return_value="active"),
            mock.patch.object(m.time,"sleep"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        m.IFACE.exists.return_value=False

    def test_order_and_no_reinstallation(self):
        self.assertEqual(m.recover(),"restored_local")
        self.assertEqual([c.args[0] for c in m.call.call_args_list],
                         [["/usr/bin/systemctl","start",u] for u in m.UNITS])
        m.verify_live.assert_called_once_with(self.g,self.e)
        self.assertGreaterEqual(m.verify_peers.call_count,2)

    def test_healthy_no_restart(self):
        m.states.return_value=("active",)*3
        self.assertEqual(m.recover(),"already_active")
        m.call.assert_not_called()

    def test_partial_state_not_touched(self):
        m.states.return_value=("active","inactive","inactive")
        with self.assertRaises(m.Blocked):
            m.recover()
        m.call.assert_not_called()

    def test_stale_interface_not_touched(self):
        m.IFACE.exists.return_value=True
        with self.assertRaises(m.Blocked):
            m.recover()
        m.call.assert_not_called()

    def test_egress_failure_rolls_back_only_exact_units(self):
        def command(args,*a,**kw):
            if args[1:]==["start",m.UNITS[2]]:
                raise subprocess.CalledProcessError(1,args)
            return mock.Mock()
        m.call.side_effect=command
        with self.assertRaises(subprocess.CalledProcessError):
            m.recover()
        self.assertEqual([c.args[0] for c in m.call.call_args_list][-3:],
                         [["/usr/bin/systemctl","stop",u] for u in reversed(m.UNITS)])
        m.verify_live.assert_not_called()

    def test_unverified_peers_never_start_egress(self):
        m.verify_peers.side_effect=m.Blocked()
        with self.assertRaises(m.Blocked):
            m.recover()
        self.assertNotIn(["/usr/bin/systemctl","start",m.UNITS[2]],
                         [c.args[0] for c in m.call.call_args_list])

if __name__=="__main__":
    unittest.main()
