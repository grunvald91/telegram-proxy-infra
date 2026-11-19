"""Offline contract tests for RU188 dedicated AWG delivery DB role/env stage.

No connection to PostgreSQL or production controller; no credentials used.
"""
from pathlib import Path
import importlib.util
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "fi_awg_worker_db_stage.py"
spec = importlib.util.spec_from_file_location("fi_awg_worker_db_stage", SCRIPT)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class AwgWorkerDbStageTests(unittest.TestCase):
    def test_billing_release_and_node_inventory_are_never_writable(self):
        captured = []
        def sql(q):
            captured.append(q)
            if "SELECT EXISTS(SELECT 1 FROM pg_roles" in q:
                return "false"
            if "FROM pg_roles WHERE" in q:
                return "false|false|false|false|false"
            if "has_table_privilege" in q:
                return "true|false|false|false"
            if q.startswith("\nBEGIN;"):
                return ""
            raise AssertionError("unexpected SQL")
        with mock.patch.object(stage, "sql", side_effect=sql):
            stage.database_role("a"*64, True)
        ddl = next(q for q in captured if q.startswith("\nBEGIN;"))
        self.assertIn("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS", ddl)
        self.assertIn("GRANT SELECT ON public.entitlements,public.vpn_release_flags,", ddl)
        self.assertNotIn("GRANT UPDATE ON public.entitlements", ddl)
        self.assertNotIn("GRANT INSERT ON public.entitlements", ddl)
        self.assertNotIn("GRANT UPDATE ON public.vpn_release_flags", ddl)
        self.assertIn("GRANT SELECT,INSERT ON public.vpn_awg_peer_allocations", ddl)
        self.assertIn("GRANT UPDATE (revision,expires_at,state,last_signed_at,", ddl)
        self.assertIn("GRANT USAGE ON SEQUENCE public.vpn_awg_command_outbox_id_seq", ddl)
        self.assertNotIn("GRANT ALL", ddl)
        self.assertNotIn("TRUNCATE", ddl)
        self.assertEqual(stage.ROLE, "mnebyvpn_awg_delivery")

    def test_existing_role_cannot_be_imported_without_protected_config(self):
        with mock.patch.object(stage, "sql", return_value="true") as sql:
            with self.assertRaises(stage.StageError):
                stage.database_role("a"*64, True)
            sql.assert_called_once()

    def test_role_removed_but_env_exists_is_rejected(self):
        with mock.patch.object(stage, "sql", return_value="false"):
            with self.assertRaises(stage.StageError):
                stage.database_role("a"*64, False)

    def test_env_is_fail_closed_without_customer_release(self):
        fields=stage.worker_fields("a"*64)
        self.assertEqual(fields["MNEBYVPN_AWG_DELIVERY_WORKER"],"disabled")
        self.assertEqual(fields["MNEBYVPN_ENV"],"production")
        self.assertEqual(fields["AWG_CONTROLLER_PUBLIC_SHA256"],stage.CONTROLLER_SHA)
        self.assertEqual(fields["AWG_CONTROLLER_SSH_IDENTITY_FILE"],str(stage.PRIVATE))
        self.assertEqual(fields["AWG_CONTROLLER_SSH_KNOWN_HOSTS_FILE"],str(stage.PIN))
        self.assertIn("127.0.0.1:55433/mnebyvpn_stage",fields["DATABASE_URL"])
        self.assertNotIn("fi_enroll",fields["DATABASE_URL"])
        code=SCRIPT.read_text()
        for prohibited in (
            "systemctl start", "systemctl enable", "docker run", "CREATE DATABASE",
            "UPDATE entitlements SET", "UPDATE vpn_release_flags SET",
            "INSERT INTO vpn_awg_peer_allocations", "subprocess.run(['ssh'",
        ):
            self.assertNotIn(prohibited,code)
        self.assertIn("awg_client_release_is_not_disabled",code)
        self.assertIn("unexpected_existing_awg_worker_approval",code)
        self.assertIn("mnebyvpn-awg-delivery.service",code)

    def test_grants_restricted_to_provisioning_module_uses(self):
        self.assertEqual(set(stage.ALLOCATION_UPDATES),
            {"revision","expires_at","state","last_signed_at","last_command_sha256","applied_at"})
        self.assertEqual(set(stage.OUTBOX_UPDATES),
            {"state","claimed_at","applied_at","attempts","node_receipt_sha256"})
        self.assertIn("vpn_awg_command_outbox", stage.EXPECTED)
        self.assertIn("vpn_node_enrollment_inventory", stage.EXPECTED)
        self.assertIn("entitlements", stage.EXPECTED)
