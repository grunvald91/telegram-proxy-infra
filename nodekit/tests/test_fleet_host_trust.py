"""Real filesystem tests: run as root on disposable /root paths; never contact VPS."""
import base64
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fleet_host_trust as m


def ssh_key(ip):
    raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"\x42" * 32
    return ip + " ssh-ed25519 " + base64.b64encode(raw).decode() + "\n"


class FleetHostTrustTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root-only disposable fixtures")
        self.root = Path(tempfile.mkdtemp(prefix="fleet-host-pin-", dir="/root"))
        os.chmod(self.root, 0o700)
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.ip = "217.11.167.91"

    def ensure(self, ip=None, key=None):
        address = ip or self.ip
        return m.ensure_pin("fi", "fi-test-01", address, root=self.root,
                            probe=lambda _: key or ssh_key(address))

    def test_controller_rejects_other_hosts_and_nonroot(self):
        with patch.object(m.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(m.TrustError, "root"):
                m.check_controller()
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.socket, "if_nameindex", return_value=[]):
            with self.assertRaisesRegex(m.TrustError, "RU188"):
                m.check_controller()
    def test_first_contact_persists_and_repeat_does_not_probe(self):
        actual, new = self.ensure()
        self.assertTrue(new)
        self.assertEqual(actual, ssh_key(self.ip))
        pin = self.root / "fi-fi-test-01.known_hosts"
        self.assertEqual(pin.read_text(), ssh_key(self.ip))
        self.assertEqual(pin.stat().st_mode & 0o077, 0)
        got, fresh = m.ensure_pin("fi", "fi-test-01", self.ip, root=self.root,
                                  probe=lambda _: self.fail("must never rescan pinned key"))
        self.assertEqual(got, actual)
        self.assertFalse(fresh)

    def test_pin_never_automatically_replaces_other_host_or_ip(self):
        self.ensure()
        with self.assertRaises(m.TrustError):
            self.ensure(ip="1.1.1.1")
        pin = self.root / "fi-fi-test-01.known_hosts"
        self.assertEqual(pin.read_text(), ssh_key(self.ip))

    def test_rejects_untrusted_targets_and_invalid_keys(self):
        for ip in ("188.120.254.223", "89.125.90.101", "127.0.0.1",
                   "10.0.0.1", "203.0.113.2", "217.11.167.091", "x;cmd"):
            with self.subTest(ip=ip), self.assertRaises(m.TrustError):
                m.check_identity("fi", "fi-test-01", ip)
        for line in ("217.11.167.91 ssh-rsa AAAA", "217.11.167.91 ssh-ed25519 AA==",
                     "89.125.90.101 " + ssh_key(self.ip).split(" ", 1)[1],
                     ssh_key(self.ip).strip() + " extra"):
            with self.subTest(line=line), self.assertRaises(m.TrustError):
                m.canonical_key(line, self.ip)

    def test_existing_symlink_or_mode_change_fails_closed(self):
        pin = self.root / "fi-fi-test-01.known_hosts"
        pin.symlink_to("/etc/passwd")
        with self.assertRaises((m.TrustError, OSError)):
            self.ensure()
        pin.unlink()
        self.ensure()
        os.chmod(pin, 0o644)
        with self.assertRaises(m.TrustError):
            self.ensure()

    def test_scanner_conflicts_fail_without_pin(self):
        with patch.object(m.subprocess, "run") as run:
            run.return_value.stdout = ssh_key(self.ip) + ssh_key(self.ip)
            with self.assertRaises(m.TrustError):
                m.discover(self.ip)
        self.assertFalse((self.root / "fi-fi-test-01.known_hosts").exists())

    def test_risky_inventory_values_not_written_as_paths(self):
        for cc, node in (("../", "fi-test-01"), ("fi", "../escape"),
                         ("FI", "fi-test-01"), ("fi", "fi_test")):
            with self.assertRaises(m.TrustError):
                m.ensure_pin(cc, node, self.ip, root=self.root,
                             probe=lambda _: ssh_key(self.ip))


if __name__ == "__main__":
    unittest.main()
