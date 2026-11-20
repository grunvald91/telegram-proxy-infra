"""Static and pin-contract tests for immutable FI AWG client worker staging."""
from pathlib import Path
import hashlib
import sys
import unittest

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
                     "runtime.verify_runtime_manifest()",
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
