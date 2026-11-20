"""FI217 production egress code cutover must be dormant, pinned and reversible."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_egress_source_cutover as m

class CutoverTests(unittest.TestCase):
    def fixture(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        (root/"releases"/m.NAME).mkdir(parents=True)
        current=(Path(__file__).parents[1]/"awg_egress.py").read_bytes()
        (root/"releases"/m.NAME/"awg_egress.py").write_bytes(current)
        self.old=b"verified old source bytes\n"
        self.target=root/"awg_egress.py"
        self.target.write_bytes(self.old)
        return root

    def run_with(self,root,*,guard=None):
        return (
            patch.object(m,"APP",root),
            patch.object(m,"TARGET",self.target),
            patch.object(m,"BACKUP",root/".fi217-awg-egress-legacy"),
            patch.object(m,"OLD",m.git_blob_id(self.old)),
            patch.object(m,"require_dormant",side_effect=guard),
            patch.object(m,"verify_stage"),
            patch.object(m,"checked_dir"),
            patch.object(m,"checked_file",side_effect=lambda path,**kw:path.read_bytes()),
        )

    def test_old_to_new_and_idempotence_and_backup(self):
        from contextlib import ExitStack
        root=self.fixture()
        with ExitStack() as stack:
            for c in self.run_with(root):stack.enter_context(c)
            self.assertEqual(m.switch(),"NEW_INACTIVE")
            self.assertEqual(m.current(),"NEW_INACTIVE")
            self.assertEqual((root/".fi217-awg-egress-legacy"/"awg_egress.legacy.py").read_bytes(),self.old)
            self.assertEqual(m.switch(),"ALREADY_SELECTED")

    def test_unknown_installed_source_refused_without_overwrite(self):
        from contextlib import ExitStack
        root=self.fixture()
        self.target.write_bytes(b"unknown")
        with ExitStack() as stack:
            for c in self.run_with(root):stack.enter_context(c)
            with self.assertRaises(m.Blocked):
                m.switch()
        self.assertEqual(self.target.read_bytes(),b"unknown")

    def test_failed_postcutover_guard_restores_legacy_source(self):
        from contextlib import ExitStack
        root=self.fixture()
        with ExitStack() as stack:
            for c in self.run_with(root,guard=[None,None,m.Blocked("service started")]):
                stack.enter_context(c)
            with self.assertRaises(m.Blocked):
                m.switch()
        self.assertEqual(self.target.read_bytes(),self.old)

    def test_no_network_or_service_activation_in_cutover(self):
        text=(Path(__file__).parents[1]/"fi_awg_egress_source_cutover.py").read_text()
        self.assertIn("require_dormant()",text)
        self.assertIn("os.replace(tmp,target)",text)
        self.assertNotIn("systemctl\", \"start",text)
        self.assertNotIn("iptables",text)
        self.assertNotIn("vpn_release_flags SET",text)
        self.assertEqual(m.OLD,"973ac8f222bf4eb32451b00fb9e8a10fa497903e")

if __name__=="__main__":unittest.main()
