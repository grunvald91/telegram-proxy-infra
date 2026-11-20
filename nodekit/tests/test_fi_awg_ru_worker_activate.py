"""RU188 worker activation must be pinned, reversible and never a release toggle."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_ru_worker_activate as m

class WorkerActivate(unittest.TestCase):
    def test_effective_pinned_requires_existing_six_source_verifier(self):
        with patch.object(m.trust,"require_safe_dormant") as a,\
             patch.object(m.pinned,"verify") as b,\
             patch.object(m.unit,"approved_base_unit") as c,\
             patch.object(m.unit,"show",return_value="/opt/mnebyvpn-controller/awg-worker-releases/446c331249085adb6536e3d9913fb4b68abf6cd7") as show:
            m.effective_pinned()
        for gate in (a,b,c):gate.assert_called_once()
        show.assert_called_once_with("WorkingDirectory")

    def test_existing_active_worker_is_verified_not_restarted(self):
        with patch.object(m,"active",return_value=True),\
             patch.object(m,"verify") as v,\
             patch.object(m,"cmd") as cmd:
            self.assertEqual(m.start(),"ALREADY_ACTIVE")
            v.assert_called_once()
            cmd.assert_not_called()

    def test_worker_failure_calls_exact_rollback(self):
        with patch.object(m,"active",return_value=False),\
             patch.object(m,"effective_pinned"),\
             patch.object(m,"ensure_marker"),\
             patch.object(m,"WANTS") as wants,\
             patch.object(m,"cmd",side_effect=RuntimeError("systemctl failure")) as cmd,\
             patch.object(m,"rollback") as undo:
            wants.exists.return_value=False
            wants.is_symlink.return_value=False
            with self.assertRaisesRegex(RuntimeError,"failure"):
                m.start()
            undo.assert_called_once_with(True,False)

    def test_does_not_modify_customer_release_or_vpn_network(self):
        src=Path(m.__file__).read_text()
        self.assertIn("pinned.verify()",src)
        self.assertNotIn("    unit.exact_effective_unit()",src)
        self.assertIn('systemctl","add-wants',src)
        self.assertNotIn("vpn_release_flags SET",src)
        self.assertNotIn("iptables",src)
        self.assertNotIn("awg-quick",src)

if __name__=="__main__":unittest.main()
