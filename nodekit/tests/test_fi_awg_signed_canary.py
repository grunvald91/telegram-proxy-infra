"""Review contract for disposable signed FI AWG peer commands.

No production key, network, subscriber, database or AWG service is accessed.
"""
import datetime as dt
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import TestCase, mock

path = Path(__file__).resolve().parents[1] / "fi_awg_signed_canary.py"
spec = importlib.util.spec_from_file_location("fi_awg_signed_canary", path)
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


class SignedAwgCanaryTests(TestCase):
    def test_exact_controller_node_contract(self):
        cmd = {
            "nodeId": "fi-test-01", "op": "grant",
            "entitlementId": "9aae0b24-7847-4e7a-bc57-3d339b292bf7",
            "revision": 1, "peerPublicKey": "A"*43+"=",
            "clientIpv4": "10.73.91.254",
            "expiresAt": "2026-11-19T11:42:00.000Z",
            "issuedAt": "2026-11-19T11:40:00.000Z",
            "nonce": "b"*64,
        }
        self.assertEqual(
            canary.message(cmd),
            b'["MNEBYVPN_AWG_LEASE_V1","fi-test-01","grant",'
            b'"9aae0b24-7847-4e7a-bc57-3d339b292bf7",1,'
            b'"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
            b'"10.73.91.254","2026-11-19T11:42:00.000Z",'
            b'"2026-11-19T11:40:00.000Z",'
            b'"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]'
        )
        self.assertEqual(canary.EXPIRY_SECONDS, 120)

    def test_ed25519_real_local_sign_and_verify(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "test-private.pem"
            pub = Path(temp) / "test-public.der"
            message = Path(temp) / "message.bin"
            signature = Path(temp) / "signature.bin"
            subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                            "-out",str(key)],check=True,capture_output=True,timeout=6)
            subprocess.run(["openssl","pkey","-in",str(key),"-pubout",
                            "-outform","DER","-out",str(pub)],check=True,
                           capture_output=True,timeout=6)
            fields = {
                "nodeId":"fi-test-01","op":"revoke",
                "entitlementId":"9aae0b24-7847-4e7a-bc57-3d339b292bf7",
                "revision":2,"peerPublicKey":"A"*43+"=",
                "clientIpv4":canary.IP,"expiresAt":None,
                "issuedAt":"2026-11-19T11:40:00.000Z","nonce":"c"*64,
            }
            signed = canary.sign(key,fields)
            self.assertEqual(len(signed["signature"]),86)
            import base64
            raw=base64.urlsafe_b64decode(signed["signature"]+"==")
            self.assertEqual(len(raw),64)
            signature.write_bytes(raw)
            message.write_bytes(canary.message(fields))
            result=subprocess.run(["openssl","pkeyutl","-verify","-pubin",
                                   "-inkey",str(pub),"-keyform","DER","-rawin",
                                   "-in",str(message),"-sigfile",str(signature)],
                                  capture_output=True,timeout=6)
            self.assertEqual(result.returncode,0)

    def test_untrusted_host_cannot_issue_or_verify(self):
        with mock.patch.object(canary,"is_host",return_value=False):
            with self.assertRaises(canary.CanaryError):
                canary.issue()
            with self.assertRaises(canary.CanaryError):
                canary.node_verify(Path("/run/nonexistent"))

    def test_expiry_is_shorter_than_offline_grant_cap_and_no_client_publish(self):
        self.assertEqual(
            canary.iso(dt.datetime(2026,11,19,11,40,tzinfo=dt.timezone.utc)),
            "2026-11-19T11:40:00.000Z"
        )
        code=path.read_text()
        for forbidden in (
            "systemctl start", "systemctl stop", "wg set", "awg syncconf",
            "iptables", "nft add", "INSERT INTO", "UPDATE entitlements",
            "peer-grants.json", "vpn_release_flags",
        ):
            self.assertNotIn(forbidden,code)
        self.assertIn("active_peers(active, utc_seconds(grant[\"expiresAt\"]) + 1)",code)
        self.assertIn('choices=("issue", "verify")', code)
        self.assertIn("transition(revoked, grant, now)",code)
        self.assertIn("REAL_PEERS_MODIFIED=false",code)
