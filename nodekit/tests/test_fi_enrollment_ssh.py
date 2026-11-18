import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_enrollment_ssh as m


def keypair(directory:Path,name:str):
    private=directory/(name+"-private.der")
    public=directory/(name+"-public.der")
    subprocess.run(["openssl","genpkey","-algorithm","ED25519","-outform","DER",
                    "-out",str(private)],check=True,capture_output=True)
    subprocess.run(["openssl","pkey","-inform","DER","-in",str(private),
                    "-pubout","-outform","DER","-out",str(public)],
                   check=True,capture_output=True)
    return private,public


def b64(x:bytes):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


class EnrollmentProofTest(unittest.TestCase):
    def test_real_openssl_signature_and_node_proof_bound_to_approved_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            node=Path(tmp)/m.NODE
            identity=node/"identity"
            identity.mkdir(parents=True)
            signer_pub=(node/"controller-access.spki")
            node_priv,node_pub=keypair(identity,"node")
            node_priv.rename(identity/"node-private.pk8")
            node_pub.rename(identity/"node-public.spki")
            controller_priv,controller_pub=keypair(node,"controller")
            controller_pub.rename(signer_pub)
            identity_bytes=(identity/"node-public.spki").read_bytes()
            controller_bytes=signer_pub.read_bytes()
            manifest={
                "node_id":m.NODE,"advertise_host":m.HOST,
                "state":"testing","registration_enabled":False,
                "activation_enabled":False,
            }
            (node/"manifest.json").write_text(json.dumps(manifest))
            now=dt.datetime(2026,11,18,10,0,0,tzinfo=dt.timezone.utc)
            challenge={
                "nodeId":m.NODE,"endpointHost":m.HOST,
                "publicSpki":b64(identity_bytes),
                "challengeId":"11111111-2222-4333-8444-555555555555",
                "nonce":b64(bytes(range(32))),
                "expiresAt":"2026-11-18T10:04:00.000Z",
            }
            challenge["controllerSignature"]=b64(m.openssl_sign(
                controller_priv,m.canonical_message(challenge)))
            sha_node=hashlib.sha256(identity_bytes).hexdigest()
            sha_controller=hashlib.sha256(controller_bytes).hexdigest()
            # The main executable enforces root-owned files. The cryptographic
            # fixture uses disposable unprivileged files and mocks ONLY ownership.
            with patch.object(m,"private_dir"), \
                 patch.object(m,"private_file",side_effect=lambda p,max_bytes=4096:p.read_bytes()):
                proof=m.sign_challenge(challenge,node,sha_node,sha_controller,now)
                self.assertEqual(proof["nodeId"],m.NODE)
                sig=m.b64(proof["signature"],m.B64_86,64)
                with tempfile.TemporaryDirectory() as tmp2:
                    path=Path(tmp2)/"proof"
                    path.write_bytes(m.proof_message(proof))
                    (Path(tmp2)/"sig").write_bytes(sig)
                    verified=subprocess.run([
                        "openssl","pkeyutl","-verify",
                        "-pubin","-inkey",str(identity/"node-public.spki"),
                        "-keyform","DER","-rawin","-in",str(path),
                        "-sigfile",str(Path(tmp2)/"sig"),
                    ],capture_output=True)
                    self.assertEqual(verified.returncode,0)
                with self.assertRaises(m.EnrollmentSshError):
                    m.sign_challenge(challenge,node,"b"*64,sha_controller,now)
                with self.assertRaises(m.EnrollmentSshError):
                    m.sign_challenge(challenge,node,sha_node,"c"*64,now)
                with self.assertRaises(m.EnrollmentSshError):
                    m.sign_challenge({**challenge,"nonce":b64(b"x"*32)},
                                     node,sha_node,sha_controller,now)
                with self.assertRaises(m.EnrollmentSshError):
                    m.sign_challenge({**challenge,"nodeId":"de-test-01"},
                                     node,sha_node,sha_controller,now)
                with self.assertRaises(m.EnrollmentSshError):
                    m.sign_challenge({**challenge,"expiresAt":"2026-11-18T09:59:00.000Z"},
                                     node,sha_node,sha_controller,now)
                with self.assertRaises(m.EnrollmentSshError):
                    m.sign_challenge({**challenge,"unexpected":"x"},
                                     node,sha_node,sha_controller,now)
                # A staged node is still not enabled or published.
                self.assertEqual(json.loads((node/"manifest.json").read_text()),manifest)
                self.assertFalse((node/"amneziawg").exists())

    def test_noncanonical_urls_and_signatures_are_rejected_before_io(self):
        malformed={
            "nodeId":m.NODE,"endpointHost":m.HOST,"publicSpki":"A"*59,
            "challengeId":"11111111-2222-4333-8444-555555555555",
            "nonce":"z"*43,"expiresAt":"2026-11-18T10:04:00.000Z",
            "controllerSignature":"A"*86,
        }
        with self.assertRaises(m.EnrollmentSshError):
            m.sign_challenge(malformed,Path("/no-such-fi-stage"),"b"*64,"c"*64,
                             dt.datetime(2026,11,18,10,tzinfo=dt.timezone.utc))
        with self.assertRaises(m.EnrollmentSshError):
            m.b64("a"*44,m.B64_43,32)

    def test_untrusted_directory_is_not_a_production_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            # No non-root-owned identity can be used for live enrollment.
            with self.assertRaises(m.EnrollmentSshError):
                m.private_dir(Path(tmp))
            with self.assertRaises(m.EnrollmentSshError):
                m.private_file(Path(tmp)/"not-an-identity")


if __name__=="__main__":
    unittest.main()
