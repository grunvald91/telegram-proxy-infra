import struct
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fi_dns_customer_policy import CustomerAuthorizer, chargeable_questions, customer_enabled
from fi_dns_metered_dot import MeteredDnsError, charge_one_question


def question(name):
    labels = [label.encode("ascii") for label in name.split(".")]
    wire = b"".join(bytes([len(label)]) + label for label in labels)
    return struct.pack("!HHHHHH", 7, 256, 1, 0, 0, 0) + wire + b"\0\0\1\0\1"


def answer(query):
    return query[:2] + bytes.fromhex("81800001000100000000") + query[12:] + bytes.fromhex("c00c000100010000003c0004c0000201")


class CustomerDnsTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_policy_charges_mapped_names_only(self):
        policy = chargeable_questions({"exact": ["www.youtube.com"], "families": ["googlevideo.com"]})
        authorizer = AsyncMock()
        authorizer.allowed.return_value = True
        meter = AsyncMock()
        meter.reserve.return_value = False
        resolver = AsyncMock()
        resolver.resolve.side_effect = answer
        name = "aaaaaaaaaaaa.fi.dns.mnebyvpn.site"

        normal = question("example.com")
        self.assertEqual(await charge_one_question(
            name, normal, authorizer=authorizer, meter=meter, resolver=resolver, chargeable=policy,
        ), answer(normal))
        meter.reserve.assert_not_called()

        for domain in ("WWW.YouTube.COM", "rr1.googlevideo.com"):
            failed = await charge_one_question(
                name, question(domain), authorizer=authorizer, meter=meter, resolver=resolver, chargeable=policy,
            )
            self.assertEqual(failed[3] & 15, 2)
        self.assertEqual(meter.reserve.await_count, 2)
        self.assertEqual(meter.release.await_count, 2)
        resolver.resolve.assert_awaited_once_with(normal)

    async def test_direct_query_cannot_pass_revocation_or_disabled_release(self):
        signed = AsyncMock()
        authorizer = CustomerAuthorizer(signed)
        with patch("fi_dns_customer_policy.customer_enabled", return_value=False):
            self.assertFalse(await authorizer.allowed("some-host"))
            signed.allowed.assert_not_called()
        with patch("fi_dns_customer_policy.customer_enabled", side_effect=[True, False]):
            signed.allowed.return_value = True
            self.assertFalse(await authorizer.allowed("some-host"))
        with patch("fi_dns_customer_policy.read", side_effect=PermissionError):
            self.assertFalse(customer_enabled())
        with patch("fi_dns_customer_policy.read", return_value=b"untrusted"):
            self.assertFalse(customer_enabled())

        direct = AsyncMock()
        direct.allowed.side_effect = [True, False]
        upstream = AsyncMock()
        upstream.resolve.side_effect = answer
        with self.assertRaisesRegex(MeteredDnsError, "grant revoked"):
            await charge_one_question(
                "aaaaaaaaaaaa.fi.dns.mnebyvpn.site", question("example.com"),
                authorizer=direct, meter=AsyncMock(), resolver=upstream, chargeable=lambda _: False,
            )
