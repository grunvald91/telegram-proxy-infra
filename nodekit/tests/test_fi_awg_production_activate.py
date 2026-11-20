"""FI217 production activation regressions: real Ed25519 and no implicit release."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_production_approval_issue as issue
import fi_awg_production_activate as rollout
import fi_awg_production_policy as policy

class ProductionBootstrapTest(unittest.TestCase):
    def test_signed_approval_matches_actual_openssl_and_exact_field_set(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            key=root/"controller-signing-key.pem"
            subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",str(key)],
                           check=True,capture_output=True)
            pub=subprocess.run(["openssl","pkey","-in",str(key),
                "-pubout","-outform","DER"],check=True,capture_output=True).stdout
            payload={
                "nodeId":"fi-test-01","endpointHost":"fi.mnebyvpn.site",
                "configSha256":"a"*64,"serverPublicKeySha256":"b"*64,
                "sourceBinarySha256":{"awg":"1"*64,"awg-quick":"2"*64,
                                      "amneziawg-go":"3"*64},
            }
            with patch.object(issue.trust,"is_host",return_value=True),\
                 patch.object(issue.trust,"RU_ROOT",root),\
                 patch.object(issue.trust,"pinned_spki",return_value=pub),\
                 patch.object(issue.trust,"protected",side_effect=lambda p,*args,**kw:p.read_bytes()),\
                 patch.object(issue,"tempfile") as tmpmodule:
                tmpmodule.TemporaryDirectory.side_effect=lambda **kwargs: tempfile.TemporaryDirectory(prefix=kwargs.get("prefix","ci-"))
                result=issue.signed(payload)
            self.assertEqual(result["approvalRevision"],1)
            self.assertEqual(result["nodeId"],"fi-test-01")
            self.assertEqual(len(base64.urlsafe_b64decode(result["signature"]+"==")),64)
            policy.verify_approval(result,pub)
            forged=dict(result,configSha256="f"*64)
            with self.assertRaises(policy.ProductionAdmissionError):
                policy.verify_approval(forged,pub)

    def test_material_cannot_override_fi_node_identity(self):
        with tempfile.TemporaryDirectory() as dirname:
            m=Path(dirname)/"material.json"
            valid={
                "nodeId":"fi-test-01","endpointHost":"fi.mnebyvpn.site",
                "configSha256":"a"*64,"serverPublicKeySha256":"b"*64,
                "sourceBinarySha256":{"awg":"1"*64,"awg-quick":"2"*64,
                                      "amneziawg-go":"3"*64},
            }
            m.write_text(json.dumps(valid))
            with patch.object(issue.trust,"protected",side_effect=lambda path,limit:path.read_bytes()):
                self.assertEqual(issue.material_file(m),valid)
                for bad in [dict(valid,nodeId="other"),dict(valid,extra="unexpected"),
                            dict(valid,sourceBinarySha256={"awg":"a"*64})]:
                    m.write_text(json.dumps(bad))
                    with self.assertRaises(issue.Refused):
                        issue.material_file(m)

    def test_converting_manifests_requires_valid_production_signature(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            node=root/"fi-test-01";awg=node/"amneziawg";awg.mkdir(parents=True)
            before_node={"node_id":"fi-test-01","advertise_host":"fi.mnebyvpn.site",
                         "state":"testing","activation_enabled":False,
                         "registration_enabled":False}
            before_awg={"node_id":"fi-test-01","state":"staged",
                        "activation_enabled":False,"peers_enabled":False,
                        "subscribers_enabled":False}
            (node/"manifest.json").write_text(json.dumps(before_node))
            (awg/"manifest.json").write_text(json.dumps(before_awg))
            def backup_for_test():
                back=node/"production-backup"
                back.mkdir(mode=0o700,exist_ok=True)
                for name in rollout.FILES:
                    (back/name.replace("/","__")).write_bytes((node/name).read_bytes())
            with patch.object(rollout,"DATA",node),\
                 patch.object(rollout,"AWG",awg),\
                 patch.object(rollout,"BACK",node/"production-backup"),\
                 patch.object(rollout,"backed_up",side_effect=backup_for_test),\
                 patch.object(rollout,"safe_manifest",side_effect=lambda path:json.loads(path.read_text())),\
                 patch.object(rollout,"APPROVAL",awg/"production-approval.json"),\
                 patch.object(rollout,"protected",side_effect=lambda path,*args:path.read_bytes()),\
                 patch.object(rollout,"admit",return_value={"production_approval":"signed"}),\
                 patch.object(rollout,"validate_awg",return_value={
                     "mode":"production","production_approval":"signed"}):
                approval={"schemaVersion":1,"nodeId":"fi-test-01","signature":"A"*86}
                rollout.configure(approval)
                self.assertEqual(rollout.state(),"PRODUCTION")
                rollout.restore()
                self.assertEqual(rollout.state(),"STAGED")
                self.assertFalse((awg/"production-approval.json").exists())

    def test_rollback_only_stops_owned_services(self):
        self.assertEqual(rollout.UNITS,(
            "mnebyvpn-nodekit-awg@fi-test-01.service",
            "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
            "mnebyvpn-nodekit-awg-egress@fi-test-01.service"))
        source=(Path(__file__).parents[1]/"fi_awg_production_activate.py").read_text()
        self.assertNotIn("vpn_release_flags SET",source)
        self.assertNotIn("systemctl stop nginx",source)
        self.assertIn("rollback()",source)
        self.assertIn('run(["systemctl","enable",unit]',source)

if __name__=="__main__":unittest.main()
