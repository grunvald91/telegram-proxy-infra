"""AWG client worker inactive cutover must preserve rollback and release gates."""
import pathlib
import unittest

HERE=pathlib.Path(__file__).resolve().parents[1]
SRC=(HERE/'fi_awg_client_worker_cutover.py').read_text()
WORKFLOW=(HERE.parent/'.github/workflows/fi-awg-client-worker-cutover.yml').read_text()

class DormantCutoverTest(unittest.TestCase):
    def test_mutation_is_only_inactive_systemd_definition(self):
        for required in (
            'oldcut.verify()', 'oldcut.verify_candidate_artifacts()',
            'client.source_and_runtime_check(blobs)',
            'oldcut.atomic_replace(target)',
            'oldcut.reload_definitions()', 'verify_unit(target)',
            'rollback(previous)', 'save_backup(previous)',
            'oldcut.acquire_lock()', 'systemd.dormant_and_disabled()',
            'ROLLBACK_READY=true', 'CLIENT_RELEASE=false',
            'BACKUP=oldcut.BACKUP_DIR',
        ):
            with self.subTest(required=required):
                self.assertIn(required,SRC)
        for forbidden in ('systemctl start','systemctl enable',
                          'UPDATE vpn_release_flags','INSERT INTO vpn_awg_'):
            self.assertNotIn(forbidden,SRC)

    def test_repeated_cutover_requires_exact_new_pinned_release(self):
        self.assertIn('elif trust.read_file(systemd.OVERRIDE,8192)==target:',SRC)
        self.assertIn('verify()',SRC)
        self.assertIn('if source==target:',SRC)
        self.assertIn('return "UNCHANGED"',SRC)
        self.assertIn('client.independently_pinned(raw,digest)',SRC)
        self.assertIn('client.RELEASE/client.MANIFEST',SRC)

    def test_pr_offline_and_main_only_live_pinned_ssh(self):
        for required in (
            'pull_request:', 'branches: [main]','needs: offline',
            "github.event_name != 'pull_request'",
            'StrictHostKeyChecking yes', 'HostKeyAlgorithms ssh-ed25519',
            'mnebydns-owner-ssh-known_hosts','--mode verify',
            'CHANGE=UNCHANGED','WORKER_ACTIVE=false;CUSTOMER_RELEASE=false',
        ):
            with self.subTest(required=required):
                self.assertIn(required,WORKFLOW)
        self.assertNotIn('StrictHostKeyChecking accept-new',WORKFLOW)
        self.assertNotIn('systemctl start',WORKFLOW)

if __name__=='__main__':unittest.main()
