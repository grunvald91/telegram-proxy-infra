"""No-client FI217 live node-key proof and anti-forgery regression."""
from __future__ import annotations
import contextlib
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import fi_awg_node_attestation as p
import fi_awg_signed_canary as c


class NodeTestProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=(ROOT/"fi_awg_node_attestation.py").read_text()

    def fixture(self):
        issued=c.iso(dt.datetime.now(dt.timezone.utc))
        common={
            "nodeId":c.NODE_ID,"entitlementId":"11111111-2222-4333-8444-555555555555",
            "peerPublicKey":"A"*43+"=","clientIpv4":c.IP,"issuedAt":issued,
        }
        return {
            "version":1,"nodeId":c.NODE_ID,
            "grant":{**common,"op":"grant","revision":1,
                     "expiresAt":issued,"nonce":"a"*64,"signature":"x"*86},
            "revoke":{**common,"op":"revoke","revision":2,
                      "expiresAt":None,"nonce":"b"*64,"signature":"y"*86},
        }

    def test_offline_challenge_binds_both_commands_and_no_ack_domain(self):
        bundle=self.fixture()
        challenge=p.make_challenge(bundle)
        self.assertEqual(challenge["schema"],p.DOMAIN)
        self.assertEqual(p.DOMAIN,"MNEBYVPN_AWG_TEST_PROOF_V1")
        self.assertNotIn("MNEBYVPN_AWG_APPLIED_V1",p.DOMAIN)
        p.check_challenge(challenge,bundle)
        broken=json.loads(json.dumps(bundle))
        broken["grant"]["nonce"]="f"*64
        with self.assertRaises(c.CanaryError):
            p.check_challenge(challenge,broken)
        self.assertEqual(set(challenge),p.EXPECTED_KEYS)

    def test_replay_and_malformed_proof_fail_closed(self):
        bundle=self.fixture()
        challenge=p.make_challenge(bundle)
        with self.assertRaises(c.CanaryError):
            p.check_challenge({**challenge,"nonce":"bad"},bundle)
        with self.assertRaises(c.CanaryError):
            p.check_challenge({**challenge,"issuedAt":"2020-01-01T00:00:00.000Z"},bundle)
        with self.assertRaises(c.CanaryError):
            p.pairs_unique([("nonce",1),("nonce",2)])
        with self.assertRaises(c.CanaryError):
            p.command_hashes({**bundle,"nodeId":"de-test-01"})

    def test_ephemeral_ed25519_roundtrip_and_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder)
            private=directory/"test-node.pk8"
            public=directory/"node-public.spki"
            msg=directory/"payload"
            sigfile=directory/"signature"
            for args in [
                ["openssl","genpkey","-algorithm","Ed25519","-outform","DER","-out",str(private)],
                ["openssl","pkey","-inform","DER","-in",str(private),
                 "-pubout","-outform","DER","-out",str(public)],
            ]:
                subprocess.run(args,check=True,capture_output=True,timeout=8)
            bundle=self.fixture()
            challenge=p.make_challenge(bundle)
            # FI and hosted runner clocks may differ by several seconds.
            proof={**challenge,"witnessedAt":c.iso(
                dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=20))}
            msg.write_bytes(p.test_payload(proof))
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(private),
                            "-keyform","DER","-rawin","-in",str(msg),
                            "-out",str(sigfile)],
                            check=True,capture_output=True,timeout=8)
            import base64
            proof["signature"]=base64.urlsafe_b64encode(sigfile.read_bytes()).rstrip(b"=").decode()
            signed=directory/"signed.json"
            challenged=directory/"challenge.json"
            received=directory/"proof.json"
            for path,data in ((signed,bundle),(challenged,challenge),(received,proof)):
                path.write_text(json.dumps(data))
                path.chmod(0o600)
            fp=hashlib.sha256(public.read_bytes()).hexdigest()
            with mock.patch.object(c,"NODE_SHA",fp):
                with contextlib.redirect_stdout(io.StringIO()) as captured:
                    p.verify(signed,challenged,received,public)
                self.assertIn("NODE_APPLIED_RECEIPT=false",captured.getvalue())
                received.write_text(json.dumps({**proof,"nonce":"0"*64}))
                with self.assertRaises(c.CanaryError):
                    p.verify(signed,challenged,received,public)
                received.write_text(json.dumps({**proof,"signature":"A"*86}))
                with self.assertRaises(c.CanaryError):
                    p.verify(signed,challenged,received,public)
                received.write_text(json.dumps({**proof,"witnessedAt":c.iso(
                    dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=45))}))
                with self.assertRaises(c.CanaryError):
                    p.verify(signed,challenged,received,public)

    def test_no_production_side_effect_or_fake_applied_ack(self):
        for forbidden in (
            "systemctl start", "systemctl enable", "systemctl restart",
            "wg set", "awg syncconf", "UPDATE entitlements", "INSERT INTO",
            "vpn_awg_command_outbox", "peer-grants.json", "controller-signing-key.pem",
        ):
            self.assertNotIn(forbidden,self.text)
        self.assertEqual(p.DOMAIN, "MNEBYVPN_AWG_TEST_PROOF_V1")
        self.assertNotEqual(p.DOMAIN, "MNEBYVPN_AWG_APPLIED_V1")
        self.assertIn("canary.node_verify(bundle_file, announce=False)",self.text)
        self.assertIn("NODE_APPLIED_RECEIPT=false",self.text)
        self.assertIn("if cmd.returncode == 0:",self.text)


if __name__=="__main__":
    unittest.main()
