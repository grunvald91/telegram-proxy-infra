"""Verify real OpenSSL Ed25519 signatures on V2 per-slot node receipts."""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_slot_contract as v2
import awg_slot_runtime as runtime


def openssl(*args):
    return subprocess.run(["openssl",*args],capture_output=True,
                          check=True,timeout=5)


class NodeV2ReceiptSignatureTest(unittest.TestCase):
    def test_real_ed25519_receipt_rejects_slot_tampering(self):
        with tempfile.TemporaryDirectory(prefix="nodekit-v2-ack-test-") as folder:
            node=pathlib.Path(folder)/"fi-test-01"
            identity=node/"identity"
            identity.mkdir(parents=True)
            priv=identity/"node-private.pk8"
            pub=identity/"node-public.spki"
            openssl("genpkey","-algorithm","ED25519","-outform","DER",
                    "-out",str(priv))
            openssl("pkey","-inform","DER","-in",str(priv),
                    "-pubout","-outform","DER","-out",str(pub))
            req={
                "nodeId":"fi-test-01","op":"grant",
                "entitlementId":"11111111-2222-4333-8444-555555555555",
                "slotNumber":2,"revision":11,
                "peerPublicKey":base64.b64encode(bytes(range(32))).decode(),
                "clientIpv4":"10.73.91.4","expiresAt":"2026-11-21T19:00:00.000Z",
                "issuedAt":"2026-11-21T18:00:00.000Z",
                "nonce":"a"*64,"signature":"B"*86,
            }
            with patch.object(runtime.v1,"protected_file",
                              side_effect=lambda path,**kwargs:
                              pathlib.Path(path).read_bytes()):
                receipt=runtime.sign_slot_node_receipt(node,req)
            self.assertEqual(receipt["slotNumber"],2)
            self.assertEqual(receipt["revision"],11)
            self.assertEqual(receipt["op"],"grant")
            self.assertEqual(receipt["commandSha256"],v2.command_digest(req))
            self.assertEqual(len(receipt["signature"]),86)
            self.assertNotIn("privateKey",json.dumps(receipt))
            payload=node/"payload"
            sig=node/"signature"
            payload.write_bytes(v2.receipt_message(receipt))
            sig.write_bytes(base64.urlsafe_b64decode(receipt["signature"]+"=="))
            openssl("pkeyutl","-verify","-pubin","-inkey",str(pub),
                    "-keyform","DER","-rawin","-in",str(payload),
                    "-sigfile",str(sig))
            changed=dict(receipt,slotNumber=3)
            payload.write_bytes(v2.receipt_message(changed))
            with self.assertRaises(subprocess.CalledProcessError):
                openssl("pkeyutl","-verify","-pubin","-inkey",str(pub),
                        "-keyform","DER","-rawin","-in",str(payload),
                        "-sigfile",str(sig))

    def test_mismatched_node_keypair_is_never_accepted(self):
        with tempfile.TemporaryDirectory(prefix="nodekit-v2-ack-keys-") as folder:
            node=pathlib.Path(folder)/"fi-test-01"
            identity=node/"identity"
            identity.mkdir(parents=True)
            priv=identity/"node-private.pk8"
            pub=identity/"node-public.spki"
            other=identity/"other-private.pk8"
            openssl("genpkey","-algorithm","ED25519","-outform","DER",
                    "-out",str(priv))
            openssl("genpkey","-algorithm","ED25519","-outform","DER",
                    "-out",str(other))
            openssl("pkey","-inform","DER","-in",str(other),
                    "-pubout","-outform","DER","-out",str(pub))
            req={"nodeId":"fi-test-01","op":"grant","entitlementId":"11111111-2222-4333-8444-555555555555",
                 "slotNumber":1,"revision":1,"peerPublicKey":base64.b64encode(bytes(range(32))).decode(),
                 "clientIpv4":"10.73.91.3","expiresAt":"2026-11-21T19:00:00.000Z",
                 "issuedAt":"2026-11-21T18:00:00.000Z","nonce":"a"*64,"signature":"B"*86}
            with patch.object(runtime.v1,"protected_file",
                              side_effect=lambda path,**kwargs:
                              pathlib.Path(path).read_bytes()):
                with self.assertRaises(runtime.SlotRuntimeError):
                    runtime.sign_slot_node_receipt(node,req)


if __name__=="__main__":
    unittest.main()
