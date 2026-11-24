import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from fi_dns_private_runtime import accept_snapshot,corefile_bytes,FI_ROOT,REGIONAL_TLS
from fi_dns_highwater import Highwater
from fi_dns_meter_rpc import timestamp

class PrivateRuntimeTests(unittest.TestCase):
    def test_derivation(self):
        raw=("tls://.:8853 {\n  bind 127.0.0.1\n  tls "+str(FI_ROOT/"tls/fullchain.pem")+" "+str(FI_ROOT/"tls/privkey.pem")+"\n  forward . tls://1.1.1.1 tls://1.0.0.1 {\n  }\n}\n").encode()
        out=corefile_bytes(raw)
        self.assertIn(str(REGIONAL_TLS/"fullchain.pem").encode(),out)
        self.assertNotIn(str(FI_ROOT/"tls/fullchain.pem").encode(),out)
        with self.assertRaises(RuntimeError):corefile_bytes(raw.replace(b"127.0.0.1",b"0.0.0.0"))

    @unittest.skipUnless(os.geteuid()==0,"root-only snapshot contract")
    def test_atomic_monotonic_empty_policy(self):
        now=time.time()
        def envelope(revision,**kwargs):
            return dict(schemaVersion=1,nodeId="fi-test-01",countryCode="FI",revision=revision,
                   issuedAt=timestamp(now-1),validUntil=timestamp(now+89),grants=[],signature="A"*86,**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/"snapshot.json";fence=Highwater(root/"highwater.json")
            verified=[]
            def verifier(*args):verified.append(args[0]["revision"])
            def accept(obj):return accept_snapshot(json.dumps(obj).encode(),now=now,path=path,highwater=fence,verifier=verifier)
            self.assertEqual(accept(envelope(2)),2)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            saved=path.read_bytes()
            with self.assertRaises(ValueError):accept(envelope(1))
            self.assertEqual(path.read_bytes(),saved)
            changed=envelope(2);changed["issuedAt"]=timestamp(now-2)
            with self.assertRaises(ValueError):accept(changed)
            expired=envelope(3);expired["validUntil"]=timestamp(now-1)
            with self.assertRaises(ValueError):accept(expired)
            self.assertEqual(path.read_bytes(),saved)
            def reject(*args):raise ValueError("bad signature")
            with self.assertRaises(ValueError):
                accept_snapshot(json.dumps(envelope(3)).encode(),now=now,path=path,highwater=fence,verifier=reject)
            self.assertEqual(path.read_bytes(),saved)
            self.assertEqual(accept(envelope(3)),3)
