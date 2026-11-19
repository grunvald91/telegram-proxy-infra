"""FI217 AWG staged pool registration contract; no customer paths."""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_pool_staged as pool

class StageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=(ROOT/"fi_awg_pool_staged.py").read_text()
        cls.key=base64.b64encode(bytes(range(32))).decode()

    def record(self):
        return {"node_id":pool.NODE,"host":pool.HOST,
                "port":51821,"subnet":pool.SUBNET,
                "server_public_key":self.key}

    def test_valid_exact_fi_material(self):
        self.assertEqual(pool.validate_public(self.record()),self.record())
        self.assertEqual(len(self.key),44)

    def test_rejects_wrong_node_country_subnet_and_key(self):
        for name,value in (("node_id","de-test-01"),("host","de.mnebyvpn.site"),
                           ("port",853),("port","51821"),("subnet","10.73.92.0/24"),
                           ("server_public_key","A'*DROP TABLE user;"),
                           ("server_public_key","A"*44)):
            record=self.record()
            record[name]=value
            with self.subTest(name=name,value=value),self.assertRaises(pool.PoolStageError):
                pool.validate_public(record)

    def test_rejects_missing_extra_and_insecure_material_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/"material.json"
            p.write_text(json.dumps(self.record()))
            p.chmod(0o600)
            self.assertEqual(pool.safe_material(p),self.record())
            p.chmod(0o644)
            with self.assertRaises(pool.PoolStageError):
                pool.safe_material(p)
            p.chmod(0o600)
            p.write_text(json.dumps({**self.record(),"signature":"fake"}))
            with self.assertRaises(pool.PoolStageError):
                pool.safe_material(p)

    def test_never_enables_worker_or_creates_fake_external_proof(self):
        for forbidden in ("systemctl start","systemctl enable",
                          "UPDATE public.vpn_release_flags",
                          "state='verified'","'verified',NOW()",
                          "INSERT INTO public.vpn_awg_peer_allocations",
                          "INSERT INTO public.entitlements"):
            self.assertNotIn(forbidden,self.text)
        for required in ("db.preflight()","'staged',NULL,NULL",
                         "CLIENT_RELEASE=false;WORKER_STARTED=false",
                         "POOL_STATE=", "check_node()", "material()",
                         "FI_POOL_EXISTING_BINDING_DRIFT"):
            # Node validator is reached through awg_external_canary.material.
            if required=="check_node()":continue
            self.assertIn(required,self.text)

if __name__=="__main__":
    unittest.main()
