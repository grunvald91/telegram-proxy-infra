"""Run against the generated country pilot, including the real TLS handler."""

import asyncio
import os
from pathlib import Path
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

if os.environ.get("FI_DNS_PILOT_TEST") != "1":
    raise unittest.SkipTest("covered by the generated pilot CI step")

from fi_dns_origin_canary import HOSTS, query_bytes
from fi_dns_pilot import PilotAuthorizer, PilotGrant
from fi_dns_signed_grants import hostname_digest
from fi_dns_tls_session import make_metered_loopback_server
import fi_routed_runtime

NAME = "123456abcdef.fi.mnebyvpn.site"
OTHER = "abcdef123456.fi.mnebyvpn.site"
QUESTION = query_bytes(0x1234, "example.com")
ANSWER = (
    struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + QUESTION[12:]
    + bytes.fromhex("c00c000100010000003c0004c0000201")
)


class PilotTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.marker = self.root / "pilot"
        self.now = int(time.time())
        self.gate = PilotGrant(self.marker)
        self.signed = AsyncMock()
        self.signed.allowed.return_value = True
        self.authorizer = PilotAuthorizer(self.signed, self.gate)
        if os.geteuid() != 0:
            trusted_dir = patch("fi_dns_pilot.private_dir")
            read_file = patch("fi_dns_pilot.read", side_effect=lambda p, n: p.read_bytes()[:n])
            trusted_dir.start()
            read_file.start()
            self.addCleanup(trusted_dir.stop)
            self.addCleanup(read_file.stop)

    def write_grant(self, name=NAME, *, issued=None, expires=None):
        issued = self.now if issued is None else issued
        expires = self.now + 90 if expires is None else expires
        self.marker.write_text(f"{hostname_digest(name)} {issued} {expires}\n")
        self.marker.chmod(0o600)

    async def test_one_valid_digest_and_signed_access_required(self):
        grant = {"tokenSha256": hostname_digest(NAME)}
        self.assertTrue(self.gate.accepts_snapshot([]))
        self.assertFalse(self.gate.accepts_snapshot([grant]))
        self.write_grant()
        self.assertTrue(self.gate.accepts_snapshot([grant]))
        self.assertFalse(self.gate.accepts_snapshot([grant, grant]))
        self.assertFalse(self.gate.accepts_snapshot([{"tokenSha256": hostname_digest(OTHER)}]))
        self.assertTrue(await self.authorizer.allowed(NAME))
        self.assertFalse(await self.authorizer.allowed(OTHER))
        self.signed.allowed.return_value = False
        self.assertFalse(await self.authorizer.allowed(NAME))
        self.write_grant(HOSTS[0])
        self.assertIsNone(self.gate.digest())
        self.write_grant(expires=self.now)
        self.assertIsNone(self.gate.digest())
        self.write_grant(issued=self.now + 50)
        self.assertIsNone(self.gate.digest())
        self.write_grant(expires=self.now + 901)
        self.assertIsNone(self.gate.digest())

    @unittest.skipUnless(os.geteuid() == 0, "root-only marker permissions")
    async def test_insecure_marker_is_rejected(self):
        self.write_grant()
        self.marker.chmod(0o644)
        self.assertIsNone(self.gate.digest())
        self.marker.unlink()
        target = self.root / "target"
        target.write_bytes(b"x")
        self.marker.symlink_to(target)
        self.assertIsNone(self.gate.digest())

    async def test_tls_counts_once_and_rechecks_existing_connection(self):
        self.write_grant()
        cert, key = self.root / "fullchain.pem", self.root / "privkey.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=*.fi.mnebyvpn.site", "-addext", "subjectAltName=DNS:*.fi.mnebyvpn.site",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        meter = AsyncMock()
        meter.reserve.return_value = meter.settle.return_value = True
        resolver = AsyncMock()
        resolver.resolve.return_value = ANSWER
        with patch("fi_dns_tls_session.REGIONAL_CERT_DIR", self.root), patch("fi_dns_tls_session.verify_pair"):
            server = await make_metered_loopback_server(
                authorizer=self.authorizer, meter=meter, resolver=resolver, listen_port=0,
            )

        async def connect(name):
            return await asyncio.open_connection(
                "127.0.0.1", server.sockets[0].getsockname()[1],
                ssl=ssl.create_default_context(cafile=str(cert)), server_hostname=name,
            )

        async def query(reader, writer):
            writer.write(struct.pack("!H", len(QUESTION)) + QUESTION)
            await writer.drain()
            header = await asyncio.wait_for(reader.read(2), timeout=5)
            return await reader.readexactly(int.from_bytes(header, "big")) if header else b""

        async with server:
            reader, writer = await connect(OTHER)
            self.assertEqual(await query(reader, writer), b"")
            writer.close()
            await writer.wait_closed()
            meter.reserve.assert_not_called()
            reader, writer = await connect(NAME)
            try:
                self.assertEqual(await query(reader, writer), ANSWER)
                self.marker.unlink()
                self.assertEqual(await query(reader, writer), b"")
            finally:
                writer.close()
                await writer.wait_closed()
        meter.reserve.assert_awaited_once()
        meter.settle.assert_awaited_once_with(meter.reserve.await_args.args[1])
        resolver.resolve.assert_awaited_once_with(QUESTION)

    async def test_revocation_during_resolution_is_not_charged(self):
        from fi_dns_metered_dot import MeteredDnsError, charge_one_question
        self.write_grant()
        meter = AsyncMock()
        meter.reserve.return_value = True
        resolver = AsyncMock()

        async def revoke(_request):
            self.marker.unlink()
            return ANSWER

        resolver.resolve.side_effect = revoke
        with self.assertRaisesRegex(MeteredDnsError, "revoked before settlement"):
            await charge_one_question(NAME, QUESTION, authorizer=self.authorizer, meter=meter, resolver=resolver)
        meter.settle.assert_not_called()
        meter.release.assert_awaited_once_with(meter.reserve.await_args.args[1])

    async def test_generated_runtime_verifies_signature_before_install(self):
        policy = {"grants": [{"tokenSha256": hostname_digest(NAME)}], "revision": 1}
        self.write_grant()
        with (
            patch("fi_routed_runtime.validate", return_value=policy),
            patch("fi_routed_runtime.PilotGrant", return_value=self.gate),
            patch("fi_routed_runtime.atomic_snapshot") as install,
        ):
            fence = Mock()
            verifier = Mock(side_effect=ValueError("invalid signature"))
            with self.assertRaisesRegex(ValueError, "invalid signature"):
                fi_routed_runtime.accept_snapshot(b"{}", highwater=fence, verifier=verifier)
            install.assert_not_called()
            verifier.side_effect = None
            self.assertEqual(fi_routed_runtime.accept_snapshot(b"{}", highwater=fence, verifier=verifier), 1)
            install.assert_called_once()
            self.marker.unlink()
            with self.assertRaisesRegex(RuntimeError, "unapproved_pilot_grant"):
                fi_routed_runtime.accept_snapshot(b"{}", highwater=fence, verifier=verifier)
            install.assert_called_once()
