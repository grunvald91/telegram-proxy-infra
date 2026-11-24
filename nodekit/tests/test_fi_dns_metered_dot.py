"""Per-question FI DoT accounting tests; no live listener or private keys."""
import asyncio
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_metered_dot as subject

HOST = "aaaaaaaaaaaa.fi.dns.mnebyvpn.site"
OTHER = "bbbbbbbbbbbb.fi.dns.mnebyvpn.site"


def question(id_=0x1234) -> bytes:
    return (struct.pack("!HHHHHH", id_, 0x0100, 1, 0, 0, 0) +
            b"\x07example\x03org\x00" +
            struct.pack("!HH", 1, 1))


def answer(q: bytes) -> bytes:
    return (q[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) +
            q[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) +
            bytes([192, 0, 2, 1]))


class Auth:
    def __init__(self, active=True):
        self.active = active
        self.calls = []

    async def allowed(self, hostname):
        self.calls.append(hostname)
        return self.active


class Meter:
    def __init__(self, budget=2, *, fail_settle=False):
        self.budget = budget
        self.fail_settle = fail_settle
        self.pending = {}
        self.settled = set()
        self.calls = []
        self.lock = asyncio.Lock()

    async def reserve(self, digest, request_id):
        async with self.lock:
            self.calls.append(("reserve", digest, request_id))
            if len(self.pending) + len(self.settled) >= self.budget:
                return False
            self.pending[request_id] = digest
            return True

    async def settle(self, request_id):
        async with self.lock:
            self.calls.append(("settle", request_id))
            if self.fail_settle or request_id not in self.pending:
                return False
            self.settled.add(request_id)
            del self.pending[request_id]
            return True

    async def release(self, request_id):
        async with self.lock:
            self.calls.append(("release", request_id))
            self.pending.pop(request_id, None)


class Resolver:
    def __init__(self, *, wrong=False, broken=False):
        self.queries = []
        self.wrong = wrong
        self.broken = broken

    async def resolve(self, q):
        self.queries.append(q)
        if self.broken:
            raise ConnectionError("upstream offline")
        if self.wrong:
            return answer(question(0xbeef))
        return answer(q)


class Writer:
    def __init__(self):
        self.data = []
        self.closed = False

    def write(self, data):
        self.data.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


async def charge(q=None, **kw):
    return await subject.charge_one_question(
        kw.pop("host", HOST), question() if q is None else q,
        authorizer=kw.pop("auth", Auth()),
        meter=kw.pop("meter", Meter()),
        resolver=kw.pop("resolver", Resolver()),
    )


class MeteredFiDotTests(unittest.TestCase):
    def test_matching_dns_question_and_answer(self):
        q=question()
        self.assertEqual(subject.question_end(q), len(q))
        subject.valid_answer(q, answer(q))
        self.assertRaises(subject.MeteredDnsError, subject.valid_answer,
                          q, answer(question(0xabcd)))
        self.assertRaises(subject.MeteredDnsError, subject.valid_answer,
                          q, answer(q)[:10])

    def test_rejects_malformed_query_without_quota_usage(self):
        q=question()
        bads=(
            b"",
            q[:1],
            q[:15],
            q[:2]+struct.pack("!H", 0x8100)+q[4:],
            q[:4]+struct.pack("!H", 2)+q[6:],
            q[:6]+struct.pack("!H", 1)+q[8:],
            q[:12]+b"\xc0\x0c"+q[-4:],
            q[:-4]+struct.pack("!HH",251,1),
            q[:-4]+struct.pack("!HH",1,3),
            q[:12]+b"\x40"+q[13:],
        )
        auth,meter,resolver=Auth(),Meter(),Resolver()
        async def go():
            for b in bads:
                with self.assertRaises(subject.MeteredDnsError):
                    await charge(b,auth=auth,meter=meter,resolver=resolver)
        asyncio.run(go())
        self.assertFalse(auth.calls)
        self.assertFalse(meter.calls)
        self.assertFalse(resolver.queries)

    def test_one_reservation_and_settlement_for_each_answer(self):
        auth,meter,resolver=Auth(),Meter(budget=2),Resolver()
        async def go():
            self.assertEqual(await charge(auth=auth,meter=meter,
                                          resolver=resolver), answer(question()))
            self.assertEqual(await charge(auth=auth,meter=meter,
                                          resolver=resolver), answer(question()))
            with self.assertRaisesRegex(subject.MeteredDnsError,"quota denied"):
                await charge(auth=auth,meter=meter,resolver=resolver)
        asyncio.run(go())
        self.assertEqual(len(auth.calls),3)
        self.assertEqual(len(meter.settled),2)
        self.assertEqual(len(resolver.queries),2)
        self.assertFalse(meter.pending)
        self.assertEqual(len([x for x in meter.calls if x[0]=="reserve"]),3)
        self.assertEqual(len([x for x in meter.calls if x[0]=="settle"]),2)

    def test_unknown_or_revoked_or_unconfigured_must_not_forward(self):
        for host in ("aaaaaaaaaaaa.de.dns.mnebyvpn.site",
                     "AAAAAAAAAAAA.fi.dns.mnebyvpn.site"):
            m,r=Meter(),Resolver()
            async def go():
                with self.assertRaises(subject.MeteredDnsError):
                    await charge(host=host,meter=m,resolver=r)
            asyncio.run(go())
            self.assertFalse(m.calls)
            self.assertFalse(r.queries)
        auth,meter,resolver=Auth(active=False),Meter(),Resolver()
        async def denied():
            with self.assertRaisesRegex(subject.MeteredDnsError,"Inactive"):
                await charge(auth=auth,meter=meter,resolver=resolver)
        asyncio.run(denied())
        self.assertFalse(meter.calls)
        self.assertFalse(resolver.queries)
        async def missing():
            for args in ({"authorizer":None,"meter":meter,"resolver":resolver},
                         {"authorizer":auth,"meter":None,"resolver":resolver},
                         {"authorizer":auth,"meter":meter,"resolver":None}):
                with self.assertRaisesRegex(subject.MeteredDnsError,"Missing required"):
                    await subject.charge_one_question(HOST,question(),**args)
        asyncio.run(missing())
        self.assertFalse(resolver.queries)

    def test_invalid_upstream_and_failed_settlement_release_quota(self):
        async def go():
            for resolver, meter in (
                (Resolver(wrong=True),Meter()),
                (Resolver(broken=True),Meter()),
                (Resolver(),Meter(fail_settle=True)),
            ):
                with self.assertRaises(Exception):
                    await charge(resolver=resolver,meter=meter)
                self.assertFalse(meter.pending)
                self.assertEqual(len(meter.settled),0)
                self.assertTrue(any(c[0]=="release" for c in meter.calls))
        asyncio.run(go())

    def test_shared_quota_concurrent_clients_cannot_exceed_limit(self):
        async def go():
            m=Meter(budget=2)
            r=Resolver()
            results=await asyncio.gather(
                *(charge(meter=m,resolver=r) for _ in range(8)),
                return_exceptions=True)
            self.assertEqual(sum(isinstance(v,bytes) for v in results),2)
            self.assertEqual(len(m.settled),2)
            self.assertEqual(len(r.queries),2)
        asyncio.run(go())

    def test_long_lived_tls_frames_reauthorize_and_stop_at_quota(self):
        async def go():
            reader=asyncio.StreamReader()
            writer=Writer()
            auth=Auth()
            meter=Meter(budget=2)
            resolver=Resolver()
            payload=struct.pack("!H",len(question()))+question()
            reader.feed_data(payload*3)
            reader.feed_eof()
            await subject.serve_one_tls_stream(
                reader,writer,HOST,authorizer=auth,
                meter=meter,resolver=resolver)
            self.assertTrue(writer.closed)
            self.assertEqual(len(writer.data),2)
            for data in writer.data:
                self.assertEqual(int.from_bytes(data[:2],"big"),len(answer(question())))
            self.assertEqual(len(auth.calls),3)
            self.assertEqual(len(resolver.queries),2)
        asyncio.run(go())

    def test_tls_upstream_only_loopback_and_regional_hostname(self):
        self.assertEqual(subject.LoopbackTlsResolver(HOST).hostname,HOST)
        with self.assertRaises(ValueError):
            subject.LoopbackTlsResolver("evil.example.org")
        with self.assertRaises(subject.MeteredDnsError):
            subject.LoopbackTlsResolver(HOST,53)
        self.assertEqual(subject.MAX_DNS_BYTES,16_384)


if __name__=="__main__":
    unittest.main()
