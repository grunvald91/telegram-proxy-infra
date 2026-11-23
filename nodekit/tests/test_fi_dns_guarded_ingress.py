"""Offline ClientHello SNI and FI regional DoT ingress regression."""
import asyncio
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_guarded_ingress as guard
import fi_dns_signed_grants as grants

HOST = "aaaaaaaaaaaa.fi.dns.mnebyvpn.site"


def tls_record(data):
    return b"\x16\x03\x01" + struct.pack("!H", len(data)) + data


def client_hello(name=HOST, *, double_sni=False):
    raw = name.encode("ascii")
    host_list = b"\x00" + struct.pack("!H", len(raw)) + raw
    server_name = struct.pack("!H", len(host_list)) + host_list
    ext = struct.pack("!HH", 0, len(server_name)) + server_name
    if double_sni:
        ext += struct.pack("!HH", 0, len(server_name)) + server_name
    body = (
        b"\x03\x03" + bytes(range(32)) + b"\x00" +
        b"\x00\x02\x13\x01" + b"\x01\x00" +
        struct.pack("!H", len(ext)) + ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return tls_record(handshake)


class FakeWriter:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True
    async def wait_closed(self):
        return None


class TestFiDoTIngress(unittest.TestCase):
    def test_sni_extracts_expected_fi_identity(self):
        wire = client_hello()
        self.assertEqual(guard.name_from_client_hello(wire), HOST)
        for n in range(len(wire)):
            with self.subTest(n=n), self.assertRaises(guard.IncompleteHello):
                guard.name_from_client_hello(wire[:n])
        self.assertEqual(guard.name_from_client_hello(wire + b"opaque_tls_bytes"),
                         HOST)

    def test_tls_handshake_record_fragmentation(self):
        wire = client_hello()
        body = wire[5:]
        split = 41
        fragmented = tls_record(body[:split]) + tls_record(body[split:])
        self.assertEqual(guard.name_from_client_hello(fragmented), HOST)

    def test_never_allows_country_swap_or_unrelated_sni(self):
        for name in [
            "aaaaaaaaaaaa.de.dns.mnebyvpn.site",
            "aaaaaaaaaaaa.dns.mnebyvpn.site",
            "aaaaaaaaaaaa.fi.dns.mnebyvpn.site.evil.com",
            "AAAAAAAAAAAA.fi.dns.mnebyvpn.site",
            "wrong",
        ]:
            with self.subTest(name=name), self.assertRaises(guard.DnsIngressError):
                guard.name_from_client_hello(client_hello(name))
        with self.assertRaises(guard.DnsIngressError):
            guard.name_from_client_hello(client_hello(double_sni=True))
        with self.assertRaises(guard.DnsIngressError):
            guard.name_from_client_hello(b"\x17" + client_hello()[1:])

    def test_overlong_preface_and_record_fail_closed(self):
        with self.assertRaises(guard.DnsIngressError):
            guard.name_from_client_hello(b"x" * (guard.PRELUDE_MAX + 1))
        with self.assertRaises(guard.DnsIngressError):
            guard.name_from_client_hello(b"\x16\x03\x01\xff\xff")
        wire = client_hello()
        with self.assertRaises(guard.DnsIngressError):
            guard.name_from_client_hello(wire[:5] + b"\x02" + wire[6:])

    def test_zero_public_listener_invariant(self):
        self.assertEqual(guard.LISTEN_IP, "127.0.0.1")
        self.assertNotEqual(guard.LISTEN_PORT, 853)
        self.assertEqual(guard.CORE_IP, "127.0.0.1")
        self.assertEqual(guard.CORE_PORT, 8853)

    def test_rejected_fifth_socket_does_not_steal_existing_counter(self):
        async def exercise():
            g = guard.Guard("f"*64)
            digest = grants.hostname_digest(HOST)
            g.connections[digest] = guard.MAX_PER_CREDENTIAL
            async def fake_prelude(_):
                return HOST, client_hello()
            with patch.object(guard, "prelude", new=fake_prelude), \
                 patch.object(guard, "load", return_value={"revision": 2}), \
                 patch.object(guard, "authorized",
                              return_value=(True, time.time()+20)):
                writer = FakeWriter()
                await g.handle(None, writer)
                self.assertTrue(writer.closed)
                self.assertEqual(g.connections[digest],
                                 guard.MAX_PER_CREDENTIAL)
                self.assertEqual(g.total, 0)
        asyncio.run(exercise())

    def test_unknown_credentials_do_not_open_upstream_socket(self):
        async def exercise():
            g = guard.Guard("f"*64)
            async def fake_prelude(_):
                return HOST, client_hello()
            with patch.object(guard, "prelude", new=fake_prelude), \
                 patch.object(guard, "load", return_value={"revision": 2}), \
                 patch.object(guard, "authorized", return_value=(False, 0.0)), \
                 patch.object(guard.asyncio, "open_connection",
                              new_callable=AsyncMock) as upstream:
                writer = FakeWriter()
                await g.handle(None, writer)
                self.assertTrue(writer.closed)
                upstream.assert_not_awaited()
                self.assertEqual(g.total, 0)
        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
