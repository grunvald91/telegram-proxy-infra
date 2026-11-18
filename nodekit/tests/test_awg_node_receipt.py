import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_peer_grants as m

class TestSignedNodeAwgReceipt(unittest.TestCase):
    def test_real_ed25519_node_ack_after_valid_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=pathlib.Path(tmp)/"fi-test-01"
            identity=node/"identity"
            identity.mkdir(parents=True)
            priv=identity/"node-private.pk8"
            pub=identity/"node-public.spki"
            subprocess.run([
                "openssl","genpkey","-algorithm","Ed25519",
                "-outform","DER","-out",str(priv),
            ],check=True,capture_output=True)
            subprocess.run([
                "openssl","pkey","-inform","DER","-in",str(priv),
                "-pubout","-outform","DER","-out",str(pub),
            ],check=True,capture_output=True)
            req={
                "nodeId":"fi-test-01","op":"grant",
                "entitlementId":"11111111-2222-4333-8444-555555555555",
                "revision":17,
                "peerPublicKey":base64.b64encode(bytes(range(32))).decode(),
                "clientIpv4":"10.73.91.2",
                "expiresAt":"2026-11-18T05:00:00.000Z",
                "issuedAt":"2026-11-18T04:00:00.000Z",
                "nonce":"a"*64,"signature":"B"*86,
            }
            with patch.object(m,"protected_file",
                              side_effect=lambda p,**kwargs:p.read_bytes()):
                receipt=m.signed_node_receipt(node,req)
            self.assertEqual(set(receipt),{
                "nodeId","op","entitlementId","revision","commandSha256",
                "appliedAt","nonce","signature",
            })
            self.assertEqual(receipt["revision"],17)
            self.assertEqual(len(receipt["nonce"]),64)
            self.assertNotIn("privateKey",json.dumps(receipt))
            payload=json.dumps([
                "MNEBYVPN_AWG_APPLIED_V1",
                receipt["nodeId"],receipt["op"],receipt["entitlementId"],
                receipt["revision"],receipt["commandSha256"],
                receipt["appliedAt"],receipt["nonce"],
            ],separators=(",",":")).encode()
            msg=pathlib.Path(tmp)/"payload"
            sig=pathlib.Path(tmp)/"signature"
            msg.write_bytes(payload)
            sig.write_bytes(base64.urlsafe_b64decode(receipt["signature"]+"=="))
            subprocess.run([
                "openssl","pkeyutl","-verify","-pubin","-inkey",str(pub),
                "-keyform","DER","-rawin","-in",str(msg),"-sigfile",str(sig),
            ],check=True,capture_output=True)
            msg.write_bytes(payload.replace(b'"grant"',b'"revoke"'))
            failed=subprocess.run([
                "openssl","pkeyutl","-verify","-pubin","-inkey",str(pub),
                "-keyform","DER","-rawin","-in",str(msg),"-sigfile",str(sig),
            ],capture_output=True)
            self.assertNotEqual(failed.returncode,0)


if __name__=="__main__":
    unittest.main()
