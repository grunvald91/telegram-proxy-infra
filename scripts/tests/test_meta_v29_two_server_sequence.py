"""Offline regression of the coordinated v29 canary order and teardown."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meta_v29_two_server_sequence as m


class TwoServerSequenceTests(unittest.TestCase):
    def recorder(self, fail=None, fail_window=False):
        actions=[]
        def run(server,command,peer):
            actions.append((server,command,peer))
            if (server,command)==fail:
                raise RuntimeError("synthetic step failure")
        def active(seconds):
            actions.append(("active","window",seconds))
            if fail_window:raise RuntimeError("synthetic client window failure")
        return actions,m.Trial(run,active)

    def test_success_stages_dns_last_and_removes_first(self):
        actions,trial=self.recorder()
        trial.run("8.8.8.8",seconds=30)
        self.assertEqual(actions,[
            ("de","stage","8.8.8.8"),
            ("ru","start","8.8.8.8"),
            ("de","enable-dns",None),
            ("active","window",30),
            ("de","disable-dns",None),
            ("ru","rollback",None),
            ("de","rollback",None)])

    def test_thirty_minute_trial_with_watchdog_margin(self):
        self.assertEqual(m.MAX_SECONDS,1800)
        actions,trial=self.recorder()
        trial.run("185.137.178.123",seconds=1800)
        self.assertIn(("active","window",1800),actions)
        self.assertEqual(actions[-1],("de","rollback",None))

    def test_failure_before_ru_never_enables_dns_but_cleans_both(self):
        actions,trial=self.recorder(fail=("ru","start"))
        with self.assertRaisesRegex(m.TrialFailure,"trial aborted"):
            trial.run("8.8.8.8")
        self.assertNotIn(("de","enable-dns",None),actions)
        self.assertEqual(actions[-3:],[("de","disable-dns",None),
            ("ru","rollback",None),("de","rollback",None)])

    def test_dns_enable_failure_aborts_and_rolls_back(self):
        actions,trial=self.recorder(fail=("de","enable-dns"))
        with self.assertRaisesRegex(m.TrialFailure,"trial aborted"):
            trial.run("8.8.8.8")
        self.assertNotIn(("active","window",900),actions)
        self.assertEqual(actions[-1],("de","rollback",None))

    def test_active_window_failure_cleans_both(self):
        actions,trial=self.recorder(fail_window=True)
        with self.assertRaises(m.TrialFailure):
            trial.run("8.8.8.8",seconds=12)
        self.assertEqual(actions[-3:],[("de","disable-dns",None),
            ("ru","rollback",None),("de","rollback",None)])

    def test_cleanup_failure_does_not_skip_other_cleanup(self):
        actions,trial=self.recorder(fail=("de","disable-dns"))
        with self.assertRaisesRegex(m.TrialFailure,"cleanup incomplete"):
            trial.run("8.8.8.8")
        self.assertEqual(actions[-1],("de","rollback",None))

    def test_invalid_ip_or_duration_makes_no_remote_calls(self):
        for peer in ("0.0.0.0","127.0.0.1","10.0.0.1",m.RU,m.DE,
                     "8.8.8.8/32","::1"):
            actions,trial=self.recorder()
            with self.subTest(peer=peer),self.assertRaises(ValueError):
                trial.run(peer)
            self.assertEqual(actions,[])
        for seconds in (0,1801,-1,True,10.2):
            actions,trial=self.recorder()
            with self.subTest(seconds=seconds),self.assertRaises(ValueError):
                trial.run("8.8.8.8",seconds=seconds)
            self.assertEqual(actions,[])


if __name__=="__main__":unittest.main()
