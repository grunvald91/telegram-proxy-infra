"""FI AWG node-pool staged-only registration contract and validation."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_node_pool_stage as p


class PoolStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=(ROOT/"fi_awg_node_pool_stage.py").read_text()
        cls.work=(ROOT.parent/".github/workflows/fi-awg-signed-offline-canary.yml").read_text()

    def test_compiles(self):
        cp=subprocess.run(["python3","-m","py_compile",
                           str(ROOT/"fi_awg_node_pool_stage.py")],
                          capture_output=True,text=True,timeout=8)
        self.assertEqual(cp.returncode,0,cp.stderr)

    def test_only_exact_fi_node_and_no_validated_node_proof(self):
        for expected in (
            '"fi-test-01"', '"fi.mnebyvpn.site"',
            '"10.73.91.0/24"', '"state": "staged"',
            "trust.require_safe_dormant()", "external_e2e_proof_sha256",
            "verified_at IS NULL", "state='staged'",
            "ON CONFLICT(node_id) DO NOTHING", "FI_AWG_NODE_POOL=STAGED",
            "PRODUCTION_E2E_VERIFIED=false",
            "AWG_WORKER_STARTED=false;CUSTOMER_RELEASE=false",
        ):
            self.assertIn(expected,self.src)
        for forbidden in (
            "systemctl start", "systemctl enable", "systemctl restart",
            "state='verified'", "verified_at=clock_timestamp()",
            "UPDATE public.", "ALTER ROLE", "GRANT SELECT",
            "vpn_awg_peer_allocations SET", "INSERT INTO public.entitlements",
            "INSERT INTO public.vpn_awg_peer_allocations",
        ):
            self.assertNotIn(forbidden,self.src)

    def test_material_file_rejects_secret_or_untrusted_values(self):
        key=base64.b64encode(bytes(32)).decode()
        good={**p.FI_POOL,"server_public_key":key}
        self.assertTrue(p.valid_key(key))
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/"data.json"
            for extra in ({"node_id":"de-test-01"},
                          {"state":"verified"},{"server_public_key":"bad"},
                          {"country_code":"FI"}):
                file.write_text(json.dumps({**good,**extra}))
                file.chmod(0o600)
                with self.assertRaises(ValueError):
                    p.read_input(file)
            file.write_text(json.dumps(good))
            file.chmod(0o600)
            if subprocess.run(["id","-u"],capture_output=True,text=True).stdout.strip()=="0":
                self.assertEqual(p.read_input(file),good)

    def test_workflow_uses_existing_two_pinned_channels_and_no_client_release(self):
        self.assertIn("nodekit/fi_awg_node_pool_stage.py",self.work)
        self.assertIn("FI_AWG_NODE_POOL=STAGED;",self.work)
        self.assertIn("UserKnownHostsFile $known",self.work)
        self.assertIn("FI_AWG_CLIENT_RELEASE_UNCHANGED=true",self.work)


if __name__=="__main__":
    unittest.main()
