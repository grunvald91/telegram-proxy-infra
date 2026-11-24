"""Real offline TLS/SNI loopback canary for the dormant FI query meter."""
import asyncio
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_tls_session as session

HOST = "aaaaaaaaaaaa.fi.dns.mnebyvpn.site"
OTHER = "bbbbbbbbbbbb.fi.dns.mnebyvpn.site"


class Authorizer:
    def __init__(self):
        self.calls = []
        self.active = True

    async def allowed(self, hostname):
        self.calls.append(hostname)
        return self.active


class Meter:
    def __init__(self, limit=2):
        self.limit = limit
        self.used = 0
        self.pending = set()
        self.calls = []
        self.lock = asyncio.Lock()

    async def reserve(self, digest, rid):
        async with self.lock:
            self.calls.append(("reserve",rid))
            if self.used + len(self.pending) >= self.limit:
                return False
            self.pending.add(rid)
            return True

    async def settle(self, rid):
        async with self.lock:
            if rid not in self.pending:
                return False
            self.pending.remove(rid)
            self.used += 1
            self.calls.append(("settle",rid))
            return True

    async def release(self, rid):
        async with self.lock:
            self.pending.discard(rid)
            self.calls.append(("release",rid))


class Resolver:
    def __init__(self):
        self.requests = []

    async def resolve(self, q):
        self.requests.append(q)
        # Standards-compliant NXDOMAIN: DNS-level negative response is still
        # a completed DNS answer and must consume one unit of query quota.
        return q[:2]+struct.pack("!HHHHH",0x8183,1,0,0,0)+q[12:]


def query():
    return (struct.pack("!HHHHHH",0x1201,0x0100,1,0,0,0)+
            b"\x07example\x03org\x00\x00\x01\x00\x01")


def certificate(directory: Path):
    subprocess.run(
        ["openssl","req","-x509","-newkey","rsa:2048","-nodes",
         "-days","3","-subj","/CN=fi.dns.test.invalid",
         "-addext","subjectAltName=DNS:*.fi.dns.mnebyvpn.site",
         "-keyout",str(directory/"privkey.pem"),
         "-out",str(directory/"fullchain.pem")],
        check=True,capture_output=True,timeout=12)


class FiMeteredTlsIntegration(unittest.TestCase):
    def test_real_tls_sni_binding_two_queries_and_quota(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            certificate(root)
            async def go():
                a,m,r=Authorizer(),Meter(limit=2),Resolver()
                with patch.object(session,"REGIONAL_CERT_DIR",root), \
                     patch.object(session,"verify_pair",return_value={"ok":True}):
                    server=await session.make_metered_loopback_server(
                        authorizer=a,meter=m,resolver=r,listen_port=0)
                try:
                    port=server.sockets[0].getsockname()[1]
                    client=ssl.create_default_context(
                        cafile=str(root/"fullchain.pem"))
                    reader,writer=await asyncio.wait_for(
                        asyncio.open_connection(
                            "127.0.0.1",port,ssl=client,server_hostname=HOST),
                        timeout=4)
                    frame=struct.pack("!H",len(query()))+query()
                    writer.write(frame*3)
                    await writer.drain()
                    responses=[]
                    for _ in range(2):
                        length=struct.unpack("!H",await reader.readexactly(2))[0]
                        responses.append(await reader.readexactly(length))
                    self.assertEqual(responses,[await r.resolve(query())]*2)
                    # Third query is denied on same TLS session; no free
                    # cached response, no extra database settlement.
                    self.assertEqual(await asyncio.wait_for(reader.read(),4),b"")
                    writer.close()
                    await writer.wait_closed()
                    self.assertEqual(m.used,2)
                    self.assertEqual(len([x for x in m.calls if x[0]=="reserve"]),3)
                    self.assertEqual(len(a.calls),3)
                    self.assertEqual(a.calls,[HOST]*3)
                    # +1 request above to build identical expected answer
                    self.assertEqual(len(r.requests),3)
                    with self.assertRaises((OSError,ssl.SSLError,ConnectionError)):
                        await asyncio.wait_for(
                            asyncio.open_connection(
                                "127.0.0.1",port,ssl=client,
                                server_hostname="unapproved.example.com"),timeout=3)
                finally:
                    server.close()
                    await server.wait_closed()
            asyncio.run(go())

    def test_no_meter_or_signer_cannot_bind_any_port(self):
        async def go():
            for auth,meter,resolver in (
                (None,Meter(),Resolver()),
                (Authorizer(),None,Resolver()),
                (Authorizer(),Meter(),None),
            ):
                with self.assertRaisesRegex(ValueError,"required"):
                    await session.make_metered_loopback_server(
                        authorizer=auth,meter=meter,resolver=resolver,
                        listen_port=18854)
        asyncio.run(go())

    def test_scope_has_no_public_or_vpn_listener(self):
        self.assertEqual(session.LISTEN_HOST,"127.0.0.1")
        self.assertNotEqual(session.LISTEN_PORT,853)
        self.assertGreaterEqual(session.GLOBAL_CONNECTIONS,1)


if __name__ == "__main__":
    unittest.main()
