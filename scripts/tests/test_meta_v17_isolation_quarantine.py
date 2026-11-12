"""Safety regression for the v16 real-device incident: no shared-edge rerun."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import meta_v15_phone_trial as controller
import meta_v15_receive_window as worker

class SharedIngressQuarantine(unittest.TestCase):
    def test_v15_live_is_quarantined_before_side_effects(self):
        with patch.object(controller, "command", side_effect=AssertionError("unexpected remote change")):
            with self.assertRaisesRegex(RuntimeError, "V15_QUARANTINED"):
                controller.live("8.8.8.8",duration=1800)

    def test_v15_live_rejects_bad_duration_early(self):
        with patch.object(controller, "command", side_effect=AssertionError("unexpected remote change")):
            with self.assertRaises(ValueError):
                controller.live("8.8.8.8",duration=3600)

    def test_document_current_shared_ip_failure_scope(self):
        """Fail if someone re-enables v15 via only a source-peer check."""
        src=Path(worker.__file__).read_text()
        from meta_v15_receive_window import nft_rules
        self.assertIn('ip saddr 8.8.8.8 ip daddr 89.125.90.101',nft_rules('89.125.90.101','8.8.8.8'))
        self.assertIn('tcp dport 443 counter dnat ip to {edge}:{port}',src)
        self.assertEqual(controller.EDGE,"89.125.90.101")
        self.assertRaises(RuntimeError,controller.require_experiment_isolation)

    def test_manual_workflow_job_disabled(self):
        wf=(Path(__file__).resolve().parents[2]/
            ".github/workflows/meta-v15-phone-canary.yml").read_text()
        self.assertIn("  canary:\n",wf)
        self.assertIn("    if: false\n",wf)

    def test_controller_does_not_silently_enable_global_dns(self):
        code=Path(controller.__file__).read_text()
        start=code.index("def live(peer, *, duration=")
        require=code.index("    require_experiment_isolation()",start)
        baseline=code.index("    route.base.baseline()",start)
        self.assertLess(require,baseline)

if __name__=="__main__":
    unittest.main()
