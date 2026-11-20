"""Signed, offline FI217 AWG production mode requires the pinned RU key."""
from __future__ import annotations
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

NODEKIT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(NODEKIT))
import fi_awg_production_policy as policy
import awg_lifecycle as lifecycle

class SignedProductionTests(unittest.TestCase):
    def setUp(self):
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL Ed25519 unavailable")
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.node=self.root/policy.NODE
        self.node.mkdir()
        key=self.root/"signing.pem"
        public=self.root/"controller.spki"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519",
                        "-out",str(key)],capture_output=True,check=True)
        subprocess.run(["openssl","pkey","-in",str(key),
                        "-pubout","-outform","DER","-out",str(public)],
                       capture_output=True,check=True)
        self.key=key
        self.pub=public.read_bytes()
        self.manifest={
            "node_id":policy.NODE,"advertise_host":policy.HOST,
            "state":"active","activation_enabled":True,
            "registration_enabled":True,
            "roles":["vpn","dns","sni-proxy","tunnel"],
        }
        self.awg={
            "node_id":policy.NODE,"state":"active",
            "activation_enabled":True,"peers_enabled":True,
            "subscribers_enabled":False,
            "source_binary_sha256":{"awg":"1"*64,"awg-quick":"2"*64,
                                    "amneziawg-go":"3"*64},
            "server_public_key":base64.b64encode(bytes(range(32))).decode(),
            "config_sha256":"a"*64,
        }
        self.approval={
            "schemaVersion":1,"nodeId":policy.NODE,"endpointHost":policy.HOST,
            "configSha256":self.awg["config_sha256"],
            "serverPublicKeySha256":hashlib.sha256(bytes(range(32))).hexdigest(),
            "sourceBinarySha256":self.awg["source_binary_sha256"].copy(),
            "approvalRevision":1,"signature":"A"*86,
        }
        self.sign(self.approval)

    def sign(self,approval):
        data=policy.approval_message(approval)
        data_file=self.root/"signed-data"
        signature=self.root/"signature"
        data_file.write_bytes(data)
        subprocess.run(["openssl","pkeyutl","-sign",
                        "-inkey",str(self.key),"-rawin","-in",str(data_file),
                        "-out",str(signature)],capture_output=True,check=True)
        approval["signature"]=base64.urlsafe_b64encode(
            signature.read_bytes()).decode().rstrip("=")

    def authorize(self,approval=None,manifest=None,awg=None):
        with mock.patch.object(policy,"safe_manifest",
                               return_value=copy.deepcopy(approval or self.approval)),\
             mock.patch.object(lifecycle,"checked_file",return_value=self.pub):
            return policy.admit(self.node,manifest or self.manifest,awg or self.awg)

    def test_real_ed25519_verification_grants_immutable_runtime_only(self):
        result=self.authorize()
        self.assertEqual(result["production_approval"],"signed")
        self.assertFalse(result["customer_release"])
        self.assertEqual(result["approved_config_identity"],"pinned")

    def test_missing_or_modified_signature_rejected(self):
        forged=copy.deepcopy(self.approval)
        forged["signature"]="A"*86
        with self.assertRaises(policy.ProductionAdmissionError):
            self.authorize(approval=forged)
        changed=copy.deepcopy(self.approval)
        changed["approvalRevision"]=2
        with self.assertRaises(policy.ProductionAdmissionError):
            self.authorize(approval=changed)

    def test_policy_cannot_be_replayed_for_another_config_or_binary(self):
        modified=copy.deepcopy(self.awg)
        modified["config_sha256"]="b"*64
        with self.assertRaises(policy.ProductionAdmissionError):
            self.authorize(awg=modified)
        modified=copy.deepcopy(self.awg)
        modified["source_binary_sha256"]["awg"]="b"*64
        with self.assertRaises(policy.ProductionAdmissionError):
            self.authorize(awg=modified)
        modified=copy.deepcopy(self.awg)
        modified["server_public_key"]=base64.b64encode(bytes(range(1,33))).decode()
        with self.assertRaises(policy.ProductionAdmissionError):
            self.authorize(awg=modified)

    def test_wrong_node_or_flags_fail_closed(self):
        for obj,key,val in (
            ("node","activation_enabled",False),
            ("node","registration_enabled",False),
            ("node","state","testing"),
            ("awg","state","staged"),
            ("awg","peers_enabled",False),
            ("awg","subscribers_enabled",True),
        ):
            with self.subTest(obj=obj,key=key):
                m=copy.deepcopy(self.manifest)
                a=copy.deepcopy(self.awg)
                (m if obj=="node" else a)[key]=val
                with self.assertRaises(policy.ProductionAdmissionError):
                    self.authorize(manifest=m,awg=a)

    def test_foreign_signer_and_bad_approval_format_rejected(self):
        foreign=bytearray(self.pub);foreign[-1]^=0x01
        with self.assertRaises(policy.ProductionAdmissionError):
            policy.verify_approval(self.approval,bytes(foreign))
        for extra in ({"signature":"x"},{"extra":"not_allowed"}):
            p=copy.deepcopy(self.approval);p.update(extra)
            with self.assertRaises(policy.ProductionAdmissionError):
                policy.approval_message(p)
        for wrong in (None,"A"*44,base64.b64encode(bytes(32)).decode()):
            with self.assertRaises(policy.ProductionAdmissionError):
                policy.canonical_key(wrong)

    def test_stage_mode_and_canary_never_gain_production_rights(self):
        with mock.patch.object(lifecycle,"validate",return_value={"mode":"production"}):
            with self.assertRaises(lifecycle.AwgLifecycleError):
                lifecycle.canary(self.node)
        source=Path(lifecycle.__file__).read_text()
        self.assertIn('allow_production=args.mode in ("validate", "inspect")',source)
        self.assertIn('if report["mode"] != "staged":',source)

if __name__=="__main__":
    unittest.main()
