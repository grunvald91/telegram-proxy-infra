"""Offline regression checks for guarded FI registration, canonical DB and no publication."""
import importlib.util
from pathlib import Path
from unittest import TestCase, mock

module_path = Path(__file__).resolve().parents[1] / "fi_registration_once.py"
spec = importlib.util.spec_from_file_location("fi_registration_once", module_path)
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


class FiRegistrationGateTests(TestCase):
    def test_absent_inventory_rejected(self):
        with mock.patch.object(registration, "execute",
                               return_value="FI_CANONICAL_DB_STATE=absent\n"):
            self.assertEqual(registration.db_state("A" * 59), "absent")

    def test_approved_and_enrolled_states_are_strict(self):
        for status in ("approved", "enrolled"):
            with self.subTest(status=status), mock.patch.object(
                registration, "execute",
                return_value="FI_CANONICAL_DB_STATE=" + status + "\n"
            ):
                self.assertEqual(registration.db_state("A" * 59), status)

    def test_fail_closed_malformed_or_duplicate_output(self):
        for raw in (
            "", "approved|fi.mnebyvpn.site", "FI_CANONICAL_DB_STATE=unknown",
            "FI_CANONICAL_DB_STATE=enrolled\nFI_CANONICAL_DB_STATE=approved",
        ):
            with self.subTest(raw=raw), mock.patch.object(
                registration, "execute", return_value=raw
            ):
                with self.assertRaises(registration.GateError):
                    registration.db_state("A" * 59)

    def test_db_state_uses_exact_registrar_systemd_env_not_stage_database(self):
        with mock.patch.object(
            registration, "execute",
            return_value="FI_CANONICAL_DB_STATE=approved"
        ) as cmd:
            self.assertEqual(registration.db_state("A" * 59), "approved")
            args = cmd.call_args.args[0]
            self.assertEqual(args[0], "systemd-run")
            self.assertIn(
                "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
                args
            )
            self.assertNotIn("docker", args)
            self.assertNotIn("mnebyvpn-stage-postgres", " ".join(args))
            self.assertIn("process.env.DATABASE_URL", registration.DB_CHECK_JS)
            self.assertIn("--property=IPAddressDeny=any", args)
            self.assertIn("--property=IPAddressAllow=127.0.0.0/8", args)

    def test_enrolled_does_not_start_systemd_enroller(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        with (
            mock.patch.object(registration.os, "geteuid", return_value=0),
            mock.patch.object(registration, "assigned_ip", return_value=True),
            mock.patch.object(registration, "spki", return_value=node),
            mock.patch.object(
                registration, "protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
            ),
            mock.patch.object(registration, "require_runtime") as require,
            mock.patch.object(registration, "db_state", return_value="enrolled"),
            mock.patch.object(registration, "execute") as cmd,
        ):
            self.assertEqual(registration.main(), 0)
            require.assert_called_once()
            cmd.assert_not_called()

    def test_absent_or_nonapproved_does_not_start_systemd_enroller(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        for state in ("absent", "planned", "revoked"):
            with (
                self.subTest(state=state),
                mock.patch.object(registration.os, "geteuid", return_value=0),
                mock.patch.object(registration, "assigned_ip", return_value=True),
                mock.patch.object(registration, "spki", return_value=node),
                mock.patch.object(
                    registration, "protected",
                    side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
                ),
                mock.patch.object(registration, "require_runtime"),
                mock.patch.object(registration, "db_state", return_value=state),
                mock.patch.object(registration, "execute") as cmd,
            ):
                with self.assertRaises(registration.GateError):
                    registration.main()
                cmd.assert_not_called()

    def test_approved_refreshes_conditions_then_checks_enrolled_in_same_db(self):
        node = bytes.fromhex("302a300506032b6570032100") + bytes(32)
        with (
            mock.patch.object(registration.os, "geteuid", return_value=0),
            mock.patch.object(registration, "assigned_ip", return_value=True),
            mock.patch.object(registration, "spki", return_value=node),
            mock.patch.object(
                registration, "protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n", b"key", b"key"]
            ),
            mock.patch.object(registration, "require_runtime"),
            mock.patch.object(
                registration, "db_state", side_effect=["approved", "enrolled"]
            ) as database,
            mock.patch.object(registration, "execute", return_value="") as execute,
        ):
            self.assertEqual(registration.main(), 0)
            self.assertEqual(database.call_count, 2)
            self.assertEqual(
                [call.args[0] for call in execute.call_args_list],
                [["systemctl","daemon-reload"],["systemctl","start",
                   "mnebyvpn-fi-enrollment.service"]]
            )

    def test_skipped_unit_requires_all_five_native_systemd_conditions_before_transient(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        commands=[]
        def cmd(args,timeout=12):
            commands.append(args)
            if args[:2]==["systemctl","show"]:
                return "no"
            if args[0]=="systemd-run":
                return "FI_ENROLLMENT=testing;SUBSCRIBER_PUBLICATION=false"
            return ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved","approved","enrolled"]) as db,
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            self.assertEqual(registration.main(),0)
        self.assertEqual(db.call_count,3)
        checks=[c for c in commands if c[0]=="systemd-analyze"]
        self.assertEqual(len(checks),5)
        transient=[c for c in commands if c[0]=="systemd-run"]
        self.assertEqual(len(transient),1)
        self.assertIn("--property=IPAddressDeny=any",transient[0])
        self.assertIn("--property=IPAddressAllow=217.11.167.91/32",transient[0])
        self.assertIn("--property=NoNewPrivileges=yes",transient[0])
        self.assertIn(
            "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
            transient[0]
        )

    def test_fallback_cannot_run_after_failed_native_condition(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        calls=[]
        def cmd(args,timeout=12):
            calls.append(args)
            if args[:2]==["systemctl","show"]:return "no"
            if args[0]=="systemd-analyze":
                raise registration.GateError("security condition denied")
            return ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved","approved"]),
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            with self.assertRaises(registration.GateError):
                registration.main()
        self.assertFalse(any(c[0]=="systemd-run" for c in calls))

    def test_fallback_cannot_run_if_static_unit_condition_is_not_skipped(self):
        node=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        commands=[]
        def cmd(args,timeout=12):
            commands.append(args)
            return "yes" if args[:2]==["systemctl","show"] else ""
        with (
            mock.patch.object(registration.os,"geteuid",return_value=0),
            mock.patch.object(registration,"assigned_ip",return_value=True),
            mock.patch.object(registration,"spki",return_value=node),
            mock.patch.object(
                registration,"protected",
                side_effect=[b"fi.mnebyvpn.site ssh-ed25519 abc\n",b"key",b"key"]
            ),
            mock.patch.object(registration,"require_runtime"),
            mock.patch.object(registration,"db_state",
                              side_effect=["approved","approved"]),
            mock.patch.object(registration,"execute",side_effect=cmd),
        ):
            with self.assertRaises(registration.GateError):
                registration.main()
        self.assertFalse(any(c[0]=="systemd-run" for c in commands))
