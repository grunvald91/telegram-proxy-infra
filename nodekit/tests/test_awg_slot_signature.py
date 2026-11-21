"""Offline cryptographic test of exact V2 Ed25519 command domain."""
import base64
import datetime as dt
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_peer_grants as v1
import awg_slot_contract as v2

NODE="fi-test-01"
UID="11111111-2222-4333-8444-555555555555"
NOW=dt.datetime.fromisoformat("2026-11-21T18:00:00+00:00").timestamp()
KEY=base64.b64encode(bytes(range(32))).decode()


class TestV2OpenSslSignature(unittest.TestCase):
    def test_real_signature_rejects_other_slots_and_v1_payload(self):
        with tempfile.TemporaryDirectory(prefix="nodekit-v2-test-") as folder:
            root=pathlib.Path(folder)
            private=root/"controller.pk8"
            public=root/"controller.spki"
            payload=root/"payload"
            signature=root/"sig"
            subprocess.run(
                ["openssl","genpkey","-algorithm","ED25519","-outform","DER",
                 "-out",str(private)],check=True,capture_output=True,timeout=5)
            subprocess.run(
                ["openssl","pkey","-inform","DER","-in",str(private),
                 "-pubout","-outform","DER","-out",str(public)],
                check=True,capture_output=True,timeout=5)
            req=dict(
                nodeId=NODE,op="grant",entitlementId=UID,slotNumber=1,
                revision=1,peerPublicKey=KEY,clientIpv4="10.73.91.3",
                expiresAt="2026-11-21T19:00:00.000Z",
                issuedAt="2026-11-21T18:00:00.000Z",
                nonce="a"*64,signature="B"*86)
            def sign_data(data: bytes) -> str:
                payload.write_bytes(data)
                subprocess.run([
                    "openssl","pkeyutl","-sign","-inkey",str(private),
                    "-keyform","DER","-rawin","-in",str(payload),
                    "-out",str(signature)
                ],check=True,capture_output=True,timeout=5)
                return base64.urlsafe_b64encode(signature.read_bytes()).rstrip(
                    b"=").decode()
            req["signature"]=sign_data(v2.signed_message(req))
            self.assertEqual(len(req["signature"]),86)
            v2.validate_command(req,NODE,NOW)
            # Tests may run as non-root; only this fixture mocks the root
            # ownership check. Real Nodekit NEVER accepts unprotected files.
            with patch.object(v2.v1,"protected_file",return_value=public.read_bytes()):
                v2.verify_signature(req,public)
                for tamper in (
                    dict(slotNumber=2),
                    dict(clientIpv4="10.73.91.4"),
                    dict(signature="B"*86),
                ):
                    with self.subTest(tamper=tamper),self.assertRaises(v2.SlotError):
                        v2.verify_signature(dict(req,**tamper),public)
                old={k:v for k,v in req.items() if k!="slotNumber"}
                old_sig=sign_data(v1.signed_message(old))
                with self.assertRaises(v2.SlotError):
                    v2.verify_signature(dict(req,signature=old_sig),public)

if __name__=="__main__":
    unittest.main()
