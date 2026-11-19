"""Non-network regression tests of least-privileged FI AWG DB role bootstrap."""
import importlib.util
from pathlib import Path
import re
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "fi_awg_delivery_db_stage.py"
spec = importlib.util.spec_from_file_location("fi_awg_delivery_db_stage", SOURCE)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class FiAwgDbRoleStageTests(unittest.TestCase):
    def test_scoped_grants_never_write_paid_entitlements_or_enrollment(self):
        sql = stage.grant_sql("f"*64, True)
        self.assertIn("CREATE ROLE mnebyvpn_awg_delivery LOGIN NOINHERIT", sql)
        for relation in (
            "entitlements", "vpn_node_enrollment_inventory",
            "vpn_awg_node_pools", "vpn_release_flags",
        ):
            self.assertIn(relation, sql)
            self.assertNotRegex(sql, r"GRANT\s+(?:UPDATE|INSERT|DELETE).*?\b" + relation + r"\b")
        for relation in ("vpn_awg_peer_allocations", "vpn_awg_command_outbox"):
            self.assertIn("ON public." + relation + " TO mnebyvpn_awg_delivery", sql)
        self.assertIn("GRANT USAGE ON SEQUENCE public.vpn_awg_command_outbox_id_seq", sql)
        self.assertNotIn("ALTER ROLE", sql)
        self.assertNotIn("UPDATE entitlements", sql)
        self.assertNotIn("INSERT INTO entitlements", sql)

    def test_worker_environment_is_private_exact_and_release_remains_off(self):
        env=stage.bootstrap_env("b"*64).decode()
        keys=[part.split("=",1)[0] for part in env.splitlines()]
        self.assertEqual(len(keys),len(set(keys)))
        self.assertIn("MNEBYVPN_AWG_DELIVERY_WORKER=enabled\n", env)
        self.assertIn("DATABASE_URL=postgresql://mnebyvpn_awg_delivery:"+"b"*64+
                      "@127.0.0.1:55433/mnebyvpn_stage\n",env)
        self.assertIn("AWG_CONTROLLER_SSH_IDENTITY_FILE=/root/mnebyvpn-controller/awg-delivery-ssh\n",env)
        source=SOURCE.read_text()
        self.assertIn("awg_worker_release_marker_must_not_be_enabled", source)
        self.assertIn("awg_worker_must_remain_off_during_staging", source)
        self.assertNotIn("systemctl start", source)
        self.assertNotIn("CREATE TABLE", source)

    def test_postgres_col_grants_verified_without_table_update(self):
        text=SOURCE.read_text()
        assert "has_any_column_privilege" in text
        assert "has_column_privilege" in text
        assert "GRANT UPDATE(revision,expires_at,state" in text
        assert "GRANT UPDATE(state,claimed_at,attempts" in text
        assert "GRANT UPDATE ON public.entitlements" not in text
        assert "GRANT UPDATE ON public.vpn_node_enrollment_inventory" not in text

    def test_existing_role_without_env_must_refuse_takeover(self):
        with mock.patch.object(stage,"preflight"), \
             mock.patch.object(stage,"role_exists",return_value=True), \
             mock.patch.object(stage.ENV,"exists",return_value=False), \
             mock.patch.object(stage.ENV,"is_symlink",return_value=False), \
             mock.patch.object(stage,"sql") as sql:
            with self.assertRaises(stage.StageError):
                stage.main()
            sql.assert_not_called()

    def test_run_state_has_no_automatic_subscription_activation(self):
        code=SOURCE.read_text()
        assert "SUBSCRIBERS_PUBLISHED=false" in code
        assert "AWG_WORKER=disabled" in code
        assert "vpn_release_flags" in code  # SELECT-only grant
        assert "APPROVAL.exists()" in code
        assert "APPROVAL.unlink" not in code
