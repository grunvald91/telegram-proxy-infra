"""Offline guard tests for the owner-approved 30-minute Meta phone trial."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import meta_v15_phone_trial as trial
from meta_v15_receive_window import MAX_LIFETIME
from mnebydns_iglite_route_only_v11 import base

class DurationSafety(unittest.TestCase):
    def test_15min_legacy_durations_unchanged(self):
        self.assertEqual(trial.time_budget(900), (1200,1500))
        self.assertEqual(trial.DEFAULT_TRIAL_SECONDS, 900)
        self.assertEqual(MAX_LIFETIME, 1500)

    def test_30min_window_and_independent_recovery_margin(self):
        watchdog, full_cleanup = trial.time_budget(1800)
        self.assertEqual((watchdog,full_cleanup),(2400,2700))
        self.assertGreater(watchdog-1800,base.MIN_ROLLBACK_MARGIN+120)
        self.assertGreaterEqual(full_cleanup-watchdog,120)

    def test_unreviewed_durations_refused(self):
        for candidate in (-1,0,1,899,901,1500,1799,1801,2400,3600):
            with self.subTest(seconds=candidate), self.assertRaises(ValueError):
                trial.time_budget(candidate)

    def test_duration_rejected_before_remote_commands(self):
        with patch.object(trial,"command",side_effect=AssertionError("unexpected command")):
            with self.assertRaises(ValueError):
                trial.live("8.8.8.8", duration=3600)

    def test_live_script_uses_both_budgets_for_recovery(self):
        source=Path(trial.__file__).read_text()
        self.assertIn('route.base.TRIAL_SECONDS=duration',source)
        self.assertIn('route.base.WATCHDOG_SECONDS=watchdog',source)
        self.assertIn('route.EXTERNAL_DEADLINE=time.monotonic()+lifetime',source)
        self.assertIn('"--on-active="+str(lifetime)+"s"',source)
        self.assertIn('"--property=RuntimeMaxSec="+str(lifetime)',source)
        self.assertIn('"--max-lifetime",str(lifetime)',source)

if __name__ == "__main__":
    unittest.main()
