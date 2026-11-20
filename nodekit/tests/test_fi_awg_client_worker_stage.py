"""Static and pin-contract tests for immutable FI AWG client worker staging."""
from pathlib import Path
import hashlib
import sys
import unittest
from unittest import mock

NODEKIT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(NODEKIT))
import fi_awg_client_worker_stage as stage

class ImmutableReleaseContract(unittest.TestCase):
    def test_reviewed_source_manifest(self):
        self.assertEqual(len(stage.FILES),6)
        self.assertEqual(stage.NEW,"446c331249085adb6536e3d9913fb4b68abf6cd7")
        self.assertIn("apps/service/src/awg-controller-delivery-worker.ts",stage.FILES)
        self.assertIn("packages/provisioning/src/awg-device-registration-worker.ts",stage.FILES)
        for name,digest in stage.FILES.items():
            with self.subTest(name=name):
                self.assertEqual(len(digest),40)
                self.assertNotIn("..",name)
                self.assertFalse(stage.independently_pinned(b"UNTRUSTED",digest))
        self.assertTrue(stage.STAGING.fullmatch("/run/fi-awg-client-worker.ZZ123456"))
        self.assertFalse(stage.STAGING.fullmatch("/tmp/fi-awg-client-worker.ZZ123456"))

    def test_existing_worker_never_starts(self):
        source=(NODEKIT/"fi_awg_client_worker_stage.py").read_text()
        for term in ("cutover.verify()","trust.require_safe_dormant()",
                     "cutover.verify()",
                     "candidate.verify_nonstandard_imports(blobs)",
                     "source_and_runtime_check(blobs)",
                     "REAL_PEERS_MODIFIED=false","CLIENT_RELEASE=false",
                     "os.O_NOFOLLOW","module" if False else "IMPORT=VERIFIED"):
            self.assertIn(term,source)
        self.assertNotIn("systemctl start",source)
        self.assertNotIn("systemctl enable",source)
        self.assertNotIn("SET enabled=true",source)
        self.assertNotIn("UPDATE vpn_release_flags",source)
        self.assertNotIn("sshpass",source)

    def test_no_reentrant_flock_on_same_release_lock(self):
        source=(NODEKIT/"fi_awg_client_worker_stage.py").read_text()
        self.assertIn("def staged_artifacts_locked() -> None:",source)
        self.assertIn("def staged_artifacts() -> None:",source)
        self.assertIn("cutover.verify()",source)
        locked=source.split("fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)",1)[1]
        locked=locked.split("fcntl.flock(fd,fcntl.LOCK_UN)",1)[0]
        self.assertNotIn("staged_artifacts()",locked)
        self.assertNotIn("cutover.verify()",locked)
        self.assertEqual(locked.count("staged_artifacts_locked()"),2)
        self.assertIn("fcntl.LOCK_EX|fcntl.LOCK_NB",source)
        self.assertIn("fi_client_worker_source_lock_busy",locked)
        workflow=(NODEKIT.parent/".github/workflows/fi-awg-client-worker-stage.yml").read_text()
        self.assertEqual(workflow.count("timeout --signal=TERM --kill-after=10s 180s"),2)
        self.assertIn("FI_AWG_SOURCE_LOCK=FREE",workflow)
        self.assertIn("flock -n -E 77",workflow)
        self.assertIn('[[ "$lock_state" == FREE ]]',workflow)
        self.assertIn("cutover.verified_new_effective_unit(",source)

    def test_postcutover_rerun_accepts_only_pinned_new_inactive_unit(self):
        import fi_awg_client_worker_cutover as clientcut
        old,new=b"reviewed-old",b"reviewed-new"
        def trusted_read(path,*args):
            if path==stage.cutover.systemd.OVERRIDE:
                return new
            if path==clientcut.BACKUP:
                return old
            raise AssertionError("Unexpected filesystem access")
        with mock.patch.object(stage.trust,"require_safe_dormant"), \
             mock.patch.object(stage.cutover,"verify_candidate_artifacts"), \
             mock.patch.object(stage,"reviewed_unit_bytes",return_value=(old,new)), \
             mock.patch.object(stage.trust,"read_file",side_effect=trusted_read), \
             mock.patch.object(clientcut,"verify_unit") as verify:
            self.assertEqual(stage.staged_artifacts_locked(),"NEW_INACTIVE")
            verify.assert_called_once_with(new)

    def test_unknown_effective_systemd_source_is_denied(self):
        with mock.patch.object(stage.trust,"require_safe_dormant"), \
             mock.patch.object(stage.cutover,"verify_candidate_artifacts"), \
             mock.patch.object(stage,"reviewed_unit_bytes",return_value=(b"old",b"new")), \
             mock.patch.object(stage.trust,"read_file",return_value=b"unapproved"):
            with self.assertRaises(stage.trust.StageBlocked):
                stage.staged_artifacts_locked()

    def test_no_existing_candidate_mutation(self):
        source=(NODEKIT/"fi_awg_client_worker_stage.py").read_text()
        self.assertIn('RELEASE=RELEASES/NEW',source)
        self.assertIn('read_file(candidate.CANDIDATE/rel)',source)
        self.assertIn('DEPENDENCY_MANIFEST=runtime.MARKER',source)
        self.assertNotIn("runtime.verify_runtime_manifest()",source)
        self.assertIn("cutover.verify()",source)
        self.assertIn('runtime.MODULES/rel',source)
        self.assertIn('matched=0',source)

if __name__=="__main__":
    unittest.main()
