"""Offline FI217 DNS country-grant tests with actual OpenSSL Ed25519."""
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_signed_grants as grants

T0 = dt.datetime(2026, 11, 23, 18, 0, 0, tzinfo=dt.timezone.utc).timestamp()
HOST = "aaaaaaaaaaaa.fi.dns.mnebyvpn.site"
OTHER = "bbbbbbbbbbbb.fi.dns.mnebyvpn.site"


def iso(seconds):
    return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def item(host=HOST, state="ACTIVE"):
    return {
        "entitlementId": str(uuid.uuid4()),
        "credentialRevision": 1,
        "tokenSha256": grants.hostname_digest(host),
        "expiresAt": iso(T0 + 3600),
        "state": state,
    }


def policy(rows=None, **kwargs):
    fields = {
        "schemaVersion": 1, "nodeId": "fi-test-01", "countryCode": "FI",
        "revision": 10, "issuedAt": iso(T0),
        "validUntil": iso(T0+90),
        "grants": [item()] if rows is None else rows,
        "signature": "A" * 86,
    }
    fields.update(kwargs)
    return fields


class FiDnsGrantsTests(unittest.TestCase):
    def test_actual_ed25519_signature_and_binding_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = root / "private.pem"
            public = root / "controller-access.spki"
            sfile = root / "snapshot.json"
            msg = root / "transcript"
            signfile = root / "signature"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                            "-out", str(private)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout",
                            "-outform", "DER", "-out", str(public)],
                           check=True, capture_output=True)
            pin = hashlib.sha256(public.read_bytes()).hexdigest()
            record = policy()
            msg.write_bytes(grants.message(record))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private),
                            "-rawin", "-in", str(msg), "-out", str(signfile)],
                           check=True, capture_output=True)
            record["signature"] = base64.urlsafe_b64encode(
                signfile.read_bytes()).rstrip(b"=").decode("ascii")
            sfile.write_text(json.dumps(record))
            with patch.object(grants, "protected_file", side_effect=lambda p, **kw: p.read_bytes()):
                good = grants.load(sfile, public, pin, now=T0+10)
                self.assertTrue(grants.authorized(good, HOST, now=T0+10)[0])
                self.assertFalse(grants.authorized(good, OTHER, now=T0+10)[0])
                self.assertFalse(grants.authorized(good, HOST, now=T0+91)[0])
                self.assertFalse(grants.authorized(
                    good, "aaaaaaaaaaaa.dns.mnebyvpn.site", now=T0+10)[0])
                with self.assertRaises(grants.RegionalDnsGrantError):
                    grants.load(sfile, public, "0"*64, now=T0+10)
                for name, tampered in [
                    ("country", dict(record, countryCode="DE")),
                    ("node", dict(record, nodeId="other-node")),
                    ("revision", dict(record, revision=9)),
                    ("grant", dict(record, grants=[item(OTHER)])),
                    ("valid_until", dict(record, validUntil=iso(T0+100))),
                ]:
                    with self.subTest(name=name):
                        sfile.write_text(json.dumps(tampered))
                        with self.assertRaises(grants.RegionalDnsGrantError):
                            grants.load(sfile, public, pin, now=T0+10)

    def test_different_regions_and_invalid_sni_always_denied(self):
        for host in [
            "aaaaaaaaaaaa.de.dns.mnebyvpn.site",
            "aaaaaaaaaaaa.dns.mnebyvpn.site",
            "aaaaaaaaaaaa.fi.dns.mnebyvpn.site.",
            "AAAAAAAAAAAA.fi.dns.mnebyvpn.site",
            "bad.aaaaaaaaaaaa.fi.dns.mnebyvpn.site",
            "aaaaaaaaaaaa.fi.dns.mnebyvpn.site.evil.com",
            "aaaaaaaaaaaa.fi.dns.mnebyvpn.site:853",
        ]:
            with self.subTest(host=host), self.assertRaises(grants.RegionalDnsGrantError):
                grants.hostname_digest(host)

    def test_grant_expiry_revoke_and_dead_snapshots(self):
        self.assertTrue(grants.authorized(policy(), HOST, now=T0+10)[0])
        self.assertFalse(grants.authorized(policy([item(state="REVOKED")]),
                                           HOST, now=T0+10)[0])
        for bad in [
            policy(validUntil=iso(T0+121)),
            policy(validUntil=iso(T0)),
            policy(issuedAt=iso(T0+30)),
            policy(nodeId="de-test-01"),
            policy(countryCode="DE"),
            policy(revision=True),
            policy(schemaVersion=True),
            policy(extra="unknown"),
            policy(grants=[item(), item()]),
            policy(grants=[dict(item(), tokenSha256="F"*64)]),
            policy(grants=[dict(item(), state="UNKNOWN")]),
            policy(grants=[dict(item(), expiresAt=iso(T0+400*86400))]),
            policy(signature="x"*85),
        ]:
            with self.subTest(bad=bad), self.assertRaises(grants.RegionalDnsGrantError):
                grants.validate(bad, now=T0+10)
        self.assertEqual(grants.validate(policy(), now=T0+10)["revision"], 10)

    def test_expired_grant_stops_active_session_without_snapshot_renewal(self):
        r = item()
        r["expiresAt"] = iso(T0+20)
        p = policy([r])
        ok, end = grants.authorized(p, HOST, now=T0+10)
        self.assertTrue(ok)
        self.assertEqual(end, T0+20)
        self.assertFalse(grants.authorized(p, HOST, now=T0+21)[0])

    def test_per_entitlement_unique_and_canonical_order(self):
        shared = str(uuid.uuid4())
        rows = [item(HOST), item(OTHER)]
        for r in rows:
            r["entitlementId"] = shared
        with self.assertRaises(grants.RegionalDnsGrantError):
            grants.validate(policy(rows), now=T0+10)
        rows = [item(HOST), item(OTHER)]
        rows.sort(key=lambda r: r["tokenSha256"], reverse=True)
        with self.assertRaises(grants.RegionalDnsGrantError):
            grants.validate(policy(rows), now=T0+10)


if __name__ == "__main__":
    unittest.main()
