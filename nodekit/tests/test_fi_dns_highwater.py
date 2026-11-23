"""Filesystem-backed anti-rollback FI DNS snapshot highwater tests.

Uses an isolated user-owned temporary directory ONLY in tests. Production
calls the identical writer with owner_uid=0 (root) on a protected node dir.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_dns_highwater as fence
from fi_dns_signed_grants import RegionalDnsGrantError


def snapshot(revision=1, *, token="a"*64):
    return {
        "schemaVersion": 1, "nodeId": "fi-test-01", "countryCode": "FI",
        "revision": revision, "issuedAt": "2026-11-23T18:00:00.000Z",
        "validUntil": "2026-11-23T18:01:30.000Z",
        "grants": [{
            "entitlementId": "11111111-1111-4111-8111-111111111111",
            "credentialRevision": 1, "tokenSha256": token,
            "expiresAt": "2026-11-24T18:00:00.000Z", "state": "ACTIVE",
        }],
    }


class TestFiDnsHighwater(unittest.TestCase):
    def test_replay_blocked_across_restart_and_same_revision_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy-highwater.json"
            uid = os.getuid()
            first = fence.Highwater(path, owner_uid=uid)
            first.observe(snapshot(11))
            saved = json.loads(path.read_text())
            self.assertEqual(saved["revision"], 11)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            # A newly started process MUST NOT lose the signed version fence.
            restarted = fence.Highwater(path, owner_uid=uid)
            restarted.observe(snapshot(11))
            with self.assertRaises(RegionalDnsGrantError):
                restarted.observe(snapshot(10))
            with self.assertRaises(RegionalDnsGrantError):
                restarted.observe(snapshot(11, token="b"*64))
            restarted.observe(snapshot(12, token="b"*64))
            self.assertEqual(json.loads(path.read_text())["revision"], 12)

    def test_symlink_instead_of_highwater_is_always_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "highwater.json"
            target = Path(tmp) / "safe.json"
            target.write_text("{}")
            path.symlink_to(target)
            with self.assertRaises(RegionalDnsGrantError):
                fence.Highwater(path, owner_uid=os.getuid()).observe(snapshot())

    def test_rejects_corruption_or_invalid_schema_no_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "highwater.json"
            for data in [
                "", "{", "{}",
                json.dumps({"version": 1, "revision": 100,
                            "transcriptSha256": "A"*64}),
                json.dumps({"version": True, "revision": 100,
                            "transcriptSha256": "a"*64}),
                json.dumps({"version": 1, "revision": -1,
                            "transcriptSha256": "a"*64}),
                "x"*257,
            ]:
                path.write_text(data)
                path.chmod(0o600)
                with self.subTest(data=data[:30]), \
                     self.assertRaises(RegionalDnsGrantError):
                    fence.Highwater(path, owner_uid=os.getuid()).observe(snapshot())

    def test_root_only_protection_rejects_world_readable_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "highwater.json"
            Path(tmp).chmod(0o755)
            try:
                with self.assertRaises(RegionalDnsGrantError):
                    fence.Highwater(path, owner_uid=os.getuid()).observe(snapshot())
            finally:
                Path(tmp).chmod(0o700)


if __name__ == "__main__":
    unittest.main()
