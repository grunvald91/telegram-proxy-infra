"""FI217 real disposable signed apply/revoke: crypto and rollback preflight."""
from __future__ import annotations
import base64
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
import fi_awg_applied_disposable_canary as mod
import fi_awg_signed_canary as issuer

class AppliedCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=(ROOT/"fi_awg_applied_disposable_canary.py").read_text()

    def build(self,op,revision):
        now=dt.datetime.now(dt.timezone.utc)
        return dict(nodeId=issuer.NODE_ID,entitlementId="11111111-2222-4333-8444-555555555555",
                    op=op,revision=revision,peerPublicKey=base64.b64encode(bytes(range(32))).decode(),
                    clientIpv4=issuer.IP,issuedAt=issuer.iso(now),
                    expiresAt=issuer.iso(now+dt.timedelta(seconds=120)) if op=="grant" else None,
                    nonce=("a" if op=="grant" else "b")*64,signature="A"*86)

    def test_independent_timer_before_any_live_awg_start(self):
        src=self.src
        self.assertIn("fi-awg-disposable-apply-expiry",src)
        self.assertIn('"--on-active=95s"',src)
        self.assertIn("cleaned=safe_cleanup(data[\"grant\"])",src)
        self.assertLess(src.index('"--on-active=95s"'),src.index('["/usr/bin/systemctl","start",UNIT]'))
        self.assertIn("if LEDGER.exists() or LEDGER.is_symlink():",src)
        self.assertIn("if not cleaned:",src)
        self.assertIn('block("cleanup_unverified_systemd_timer_remains_armed")',src)
        self.assertNotIn("vpn_release_flags SET",src)
        self.assertNotIn("UPDATE entitlements",src)

    def test_verified_node_receipts_are_real_applied_domain(self):
        with tempfile.TemporaryDirectory() as folder:
            tmp=Path(folder)
            private,pub=tmp/"private.pk8",tmp/"public.spki"
            for args in (
                ["openssl","genpkey","-algorithm","Ed25519","-outform","DER","-out",str(private)],
                ["openssl","pkey","-inform","DER","-in",str(private),
                 "-pubout","-outform","DER","-out",str(pub)]
            ):
                subprocess.run(args,check=True,capture_output=True,timeout=8)
            signed={"version":1,"nodeId":issuer.NODE_ID,
                    "grant":self.build("grant",1),"revoke":self.build("revoke",2)}
            bundle=tmp/"signed.json"
            bundle.write_text(json.dumps(signed))
            receipts={}
            for op in ("grant","revoke"):
                cmd=signed[op]
                receipt=dict(nodeId=issuer.NODE_ID,op=op,entitlementId=cmd["entitlementId"],
                             revision=cmd["revision"],
                             commandSha256=hashlib.sha256(issuer.message(cmd)).hexdigest(),
                             appliedAt=issuer.iso(dt.datetime.now(dt.timezone.utc)),
                             nonce=("c" if op=="grant" else "d")*64)
                raw=json.dumps(["MNEBYVPN_AWG_APPLIED_V1",issuer.NODE_ID,op,
                  receipt["entitlementId"],receipt["revision"],receipt["commandSha256"],
                  receipt["appliedAt"],receipt["nonce"]],separators=(",",":"),ensure_ascii=False).encode()
                payload,sig=tmp/(op+"-payload"),tmp/(op+"-signature")
                payload.write_bytes(raw)
                subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(private),
                    "-keyform","DER","-rawin","-in",str(payload),"-out",str(sig)],
                    check=True,capture_output=True,timeout=8)
                receipt["signature"]=base64.urlsafe_b64encode(sig.read_bytes()).rstrip(b"=").decode()
                receipts[op+"Receipt"]=receipt
            report={"version":1,"nodeId":issuer.NODE_ID,
                    "publicCustomerRelease":False,"realGrantApplied":True,
                    "realRevokeApplied":True,"peersLeft":0,**receipts}
            receipt_file=tmp/"receipts.json"
            receipt_file.write_text(json.dumps(report))
            sha=hashlib.sha256(pub.read_bytes()).hexdigest()
            with mock.patch.object(issuer,"NODE_SHA",sha):
                with contextlib.redirect_stdout(io.StringIO()) as buffer:
                    mod.verify_output(bundle,receipt_file,pub)
                self.assertIn("SIGNED_REVOKE_ACK=true",buffer.getvalue())
                bad=json.loads(json.dumps(report))
                bad["grantReceipt"]["nonce"]="f"*64
                receipt_file.write_text(json.dumps(bad))
                with self.assertRaises(mod.CanaryBlocked):
                    mod.verify_output(bundle,receipt_file,pub)
                bad=json.loads(json.dumps(report))
                bad["publicCustomerRelease"]=True
                receipt_file.write_text(json.dumps(bad))
                with self.assertRaises(mod.CanaryBlocked):
                    mod.verify_output(bundle,receipt_file,pub)
if __name__=="__main__":unittest.main()
