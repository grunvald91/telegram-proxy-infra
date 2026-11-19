"""Offline regression checks for fail-closed FI registration."""
import importlib.util
from pathlib import Path
from unittest import TestCase, mock

module_path = Path(__file__).resolve().parents[1] / "fi_registration_once.py"
spec = importlib.util.spec_from_file_location("fi_registration_once", module_path)
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


class FiRegistrationGateTests(TestCase):
    def test_requires_approved_inventory_row(self):
        with mock.patch.object(registration, "execute", return_value=""):
            with self.assertRaises(registration.GateError):
                registration.db_state("approved-public-spki")

    def test_mismatched_identity_fails_closed(self):
        for row in (
            "approved|other.example|abc|true|false",
            "approved|fi.mnebyvpn.site|wrong|true|false",
            "approved|fi.mnebyvpn.site|abc|false|false",
            "approved|fi.mnebyvpn.site|abc|true|true",
        ):
            with self.subTest(row=row), mock.patch.object(
                registration, "execute", return_value=row
            ):
                with self.assertRaises(registration.GateError):
                    registration.db_state("abc")

    def test_enrolled_is_idempotent(self):
        with mock.patch.object(
            registration, "execute",
            return_value="enrolled|fi.mnebyvpn.site|abc|true|true"
        ):
            self.assertEqual(registration.db_state("abc"), "enrolled")

    def test_approved_is_not_enrolled(self):
        with mock.patch.object(
            registration, "execute",
            return_value="approved|fi.mnebyvpn.site|abc|true|false"
        ):
            self.assertEqual(registration.db_state("abc"), "approved")

    def test_no_activation_when_approval_file_missing(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        value = registration.base64.urlsafe_b64encode(node).decode().rstrip("=")
        row = f"approved|fi.mnebyvpn.site|{value}|true|false"
        with (
            mock.patch.object(registration.os, "geteuid", return_value=0),
            mock.patch.object(registration, "assigned_ip", return_value=True),
            mock.patch.object(registration, "spki", return_value=node),
            mock.patch.object(
                registration, "protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
            ),
            mock.patch.object(registration, "execute", return_value=row) as cmd,
            mock.patch.object(
                registration, "require_runtime",
                side_effect=registration.GateError("missing approval")
            ),
        ):
            with self.assertRaises(registration.GateError):
                registration.main()
            self.assertEqual(cmd.call_count, 1)
            self.assertEqual(cmd.call_args.args[0][:2], ["docker", "exec"])
