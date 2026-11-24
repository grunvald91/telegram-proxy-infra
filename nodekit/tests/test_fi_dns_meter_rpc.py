import asyncio
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_dns_meter_rpc as rpc
from fi_enrollment_ssh import openssl_sign, openssl_verify

# Independent Node.js implementation of the RU188 transcript with real keys.
NODE_CODE = """
const fs=require('node:fs'),c=require('node:crypto');
const r=JSON.parse(fs.readFileSync(0,'utf8'));
const raw=Buffer.from(JSON.stringify(['MNEBYVPN_FI_DNS_METER_REQUEST_V1',r.version,r.nodeId,r.countryCode,r.op,r.requestId,r.tokenSha256,r.issuedAt,r.nonce]));
const key=c.createPublicKey({key:fs.readFileSync(process.argv[1]),format:'der',type:'spki'});
if(!c.verify(null,raw,key,Buffer.from(r.signature,'base64url')))process.exit(2);
const d={version:1,requestSha256:c.createHash('sha256').update(raw).digest('hex'),
 result:r.op==='reserve'?'RESERVED':r.op==='settle'?'SETTLED':'RELEASED',decidedAt:r.issuedAt};
const msg=Buffer.from(JSON.stringify(['MNEBYVPN_FI_DNS_METER_DECISION_V1',d.version,d.requestSha256,d.result,d.decidedAt]));
const privateKey=c.createPrivateKey({key:fs.readFileSync(process.argv[2]),format:'der',type:'pkcs8'});
d.signature=c.sign(null,msg,privateKey).toString('base64url');
process.stdout.write(JSON.stringify(d));
"""


class MeterClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_python_node_ed25519_roundtrip_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ("node","controller"):
                subprocess.run(["openssl","genpkey","-algorithm","ED25519",
                                "-outform","DER","-out",str(root/(name+".key"))],
                               check=True,capture_output=True,timeout=5)
                subprocess.run(["openssl","pkey","-inform","DER","-in",str(root/(name+".key")),
                                "-pubout","-outform","DER","-out",str(root/(name+".pub"))],
                               check=True,capture_output=True,timeout=5)
            requests=[]
            async def transport(raw):
                requests.append(json.loads(raw))
                return (await asyncio.to_thread(subprocess.run,
                    ["node","-e",NODE_CODE,str(root/"node.pub"),str(root/"controller.key")],
                    input=raw,capture_output=True,check=True,timeout=5)).stdout
            def sign(message):
                return openssl_sign(root/"node.key",message)
            def verify(message,signature):
                openssl_verify(root/"controller.pub",signature,message)
            meter=rpc.SignedQueryMeter(transport,sign,verify)
            rid=uuid.uuid4()
            self.assertTrue(await meter.reserve("a"*64,rid))
            self.assertTrue(await meter.settle(rid))
            await meter.release(rid)
            self.assertEqual([x["op"] for x in requests],["reserve","settle","release"])
            self.assertEqual(len({x["nonce"] for x in requests}),3)
            self.assertEqual({x["requestId"] for x in requests},{str(rid)})
            self.assertIsNone(requests[1]["tokenSha256"])

            async def wrong(raw):
                reply=json.loads(await transport(raw))
                reply["result"]="DENY_QUOTA"
                return json.dumps(reply).encode()
            with self.assertRaises(ValueError):
                await rpc.SignedQueryMeter(wrong,sign,verify).reserve("a"*64,uuid.uuid4())

            async def duplicate(raw):
                reply=await transport(raw)
                return b'{"version":1,'+reply[1:]
            with self.assertRaises(ValueError):
                await rpc.SignedQueryMeter(duplicate,sign,verify).reserve("a"*64,uuid.uuid4())
            with self.assertRaises(rpc.MeterRpcError):
                await rpc.SignedQueryMeter(transport,sign,lambda *_:False).reserve("a"*64,uuid.uuid4())

    async def test_invalid_input_never_reaches_transport(self):
        async def transport(_):
            self.fail("invalid input reached transport")
        meter=rpc.SignedQueryMeter(transport,lambda _:b"x"*64,lambda *_:None)
        with self.assertRaises(rpc.MeterRpcError):
            await meter.reserve("bad",uuid.uuid4())
        with self.assertRaises(rpc.MeterRpcError):
            await meter.settle(uuid.uuid1())

    def test_fresh_decision_does_not_revive_stale_original(self):
        now=1795521600.0
        request={"version":1,"nodeId":"fi-test-01","countryCode":"FI",
                 "op":"reserve","requestId":str(uuid.uuid4()),
                 "tokenSha256":"a"*64,"issuedAt":rpc.timestamp(now),"nonce":"b"*64}
        decision={"version":1,"requestSha256":hashlib.sha256(rpc.request_bytes(request)).hexdigest(),
                  "result":"RESERVED","decidedAt":rpc.timestamp(now+14),
                  "signature":base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()}
        raw=json.dumps(decision).encode()
        rpc.validate_decision(raw,request,now+14)
        with self.assertRaises(rpc.MeterRpcError):
            rpc.validate_decision(raw,request,now+16)
