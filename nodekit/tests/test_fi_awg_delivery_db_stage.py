"""Non-network regression tests of least-privileged FI AWG DB role bootstrap."""
import importlib.util
from pathlib import Path
import re
import tempfile
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

    def test_orphan_role_repair_fails_closed_if_privileges_not_exact(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(stage,"ENV",Path(temp)/"missing.env"), \
             mock.patch.object(stage,"preflight"), \
             mock.patch.object(stage,"role_exists",return_value=True), \
             mock.patch.object(stage,"verify_privileges",side_effect=stage.StageError("unsafe")), \
             mock.patch.object(stage,"environment") as env, \
             mock.patch.object(stage,"sql") as sql:
            with self.assertRaises(stage.StageError):
                stage.main()
            env.assert_not_called()
            sql.assert_not_called()

    def test_known_safe_orphan_role_is_recovered_without_broad_grants(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(stage,"ENV",Path(temp)/"missing.env"), \
             mock.patch.object(stage,"preflight"), \
             mock.patch.object(stage,"role_exists",return_value=True), \
             mock.patch.object(stage,"verify_privileges") as validate, \
             mock.patch.object(stage,"environment",return_value=("f"*64,True)), \
             mock.patch.object(stage,"verify_login") as login, \
             mock.patch.object(stage,"sql") as sql:
            stage.main()
            self.assertEqual(validate.call_count,2)
            sql.assert_called_once()
            self.assertEqual(sql.call_args.args[0],
                             "ALTER ROLE mnebyvpn_awg_delivery PASSWORD '"+("f"*64)+"';")
            login.assert_called_once_with("f"*64)

    def test_acl_probe_uses_any_column_not_table_wide_permission(self):
        source=SOURCE.read_text()
        self.assertGreaterEqual(source.count("has_any_column_privilege"),4)
        def permissions(statement):
            if "FROM pg_roles r" in statement:
                return "true|false|false|false|false|false|false|0"
            if "has_sequence_privilege" in statement:
                return "true"
            if "has_column_privilege" in statement:
                return "false"
            if "has_table_privilege" in statement:
                if any("public."+name in statement for name in
                       ("entitlements","vpn_node_enrollment_inventory",
                        "vpn_awg_node_pools","vpn_release_flags")):
                    return "true|false|false|false"
                return "true|true|true|false"
            raise AssertionError("unexpected SQL")
        with mock.patch.object(stage,"sql",side_effect=permissions):
            stage.verify_privileges()
        self.assertNotIn("BEGIN READ ONLY",source)
        self.assertIn("ROW_LOCK_GATEWAY_READY=false",source)
        self.assertIn("phase='read_permissions'",source)
        self.assertNotIn("LIMIT 0 FOR SHARE",source)
        self.assertIn("SELECT * FROM public.'+table+' LIMIT 0",source)
        self.assertNotIn("GRANT UPDATE ON public.entitlements",source)


    def test_run_state_has_no_automatic_subscription_activation(self):
        code=SOURCE.read_text()
        assert "SUBSCRIBERS_PUBLISHED=false" in code
        assert "AWG_WORKER=disabled" in code
        assert "vpn_release_flags" in code  # SELECT-only grant
        assert "APPROVAL.exists()" in code
        assert "APPROVAL.unlink" not in code

    def test_role_login_audit_exposes_only_phase_and_code(self):
        source=SOURCE.read_text()
        self.assertIn("current_user AS role_name",source)
        self.assertNotIn("current_user AS user",source)
        self.assertIn("FI_AWG_DB_LOGIN_CHECK_PHASE=",source)
        self.assertIn("PG_CODE=",source)
        self.assertIn('re.fullmatch(',source)
        self.assertNotIn('print(result.stderr',source)
