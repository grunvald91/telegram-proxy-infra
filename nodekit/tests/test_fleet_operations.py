import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fleet_operations as f

GOOD = {
 "schema_version":1, "operation":"stage_telemt", "country_code":"FI",
 "node_id":"fi-test-01", "advertise_host":"fi.mnebyvpn.site",
 "ssh_ipv4":"217.11.167.91", "approved":True,
 "subscriber_publication_allowed":False
}
INVENTORY = {
 "schema_version":1, "country_code":"FI", "node_id":"fi-test-01",
 "advertise_host":"fi.mnebyvpn.site", "ssh_ipv4":"217.11.167.91",
 "role":"combined", "services":["dns","vpn","sni-proxy","tunnel"],
 "listeners":{"dot_tcp":853,"vpn_tcp":2053,"sni_tcp":443,"tunnel_udp":51820},
 "status":"testing", "automatic_bootstrap_allowed":True,
 "subscriber_publication_allowed":False, "expected_identity_public_sha256":None
}
PATH = "nodekit/fleet-operations/fi-telemt-stage-20261123.json"

class FleetOperationTests(unittest.TestCase):
    def setup_fixture(self, root, value=GOOD):
        op = root / PATH
        op.parent.mkdir(parents=True,exist_ok=True)
        op.write_text(json.dumps(value))
        inv = root/"nodekit/fleet/fi.json"
        inv.parent.mkdir(parents=True,exist_ok=True)
        inv.write_text(json.dumps(INVENTORY))
        return op

    def test_exact_one_shot_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.setup_fixture(root)
            self.assertEqual(f.select([PATH],root),[("fi","telemt-stage")])
            self.assertEqual(f.select([],root),[])

    def test_refuse_unreviewed_or_changed_target(self):
        for patch in [
            {"approved":False},{"subscriber_publication_allowed":True},
            {"operation":"auto"},{"node_id":"other"},{"ssh_ipv4":"1.1.1.1"},
            {"country_code":"DE"},{"schema_version":True},{"unexpected":1},
        ]:
            with self.subTest(patch=patch), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                self.setup_fixture(root,{**GOOD,**patch})
                with self.assertRaises((f.OperationError, ValueError)):
                    f.plan(PATH,root)

    def test_reject_duplicate_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            op=self.setup_fixture(root)
            with self.assertRaises(f.OperationError):
                f.select([PATH,PATH],root)
            op.unlink()
            op.symlink_to(root / "nodekit/fleet/fi.json")
            with self.assertRaises(f.OperationError):
                f.plan(PATH,root)

    def test_reject_ambiguous_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.setup_fixture(root)
            with self.assertRaises(f.OperationError):
                f.plan("nodekit/fleet-operations/../fleet/fi.json",root)

if __name__=="__main__":
    unittest.main()
