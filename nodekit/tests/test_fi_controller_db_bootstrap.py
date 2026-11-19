"""Fail-closed checks for FI217 DB bootstrap. No production DB is used."""
import importlib.util
import json
from pathlib import Path
from unittest import TestCase, mock

path = Path(__file__).resolve().parents[1]/"fi_controller_db_bootstrap.py"
spec = importlib.util.spec_from_file_location("fi_db_bootstrap",path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FiDbBootstrapTests(TestCase):
    def test_root_only_canonical_environment_contains_scoped_role(self):
        fields=module.env_fields("a"*64)
        self.assertEqual(fields["MNEBYVPN_ENV"],"production")
        self.assertEqual(fields["MNEBYVPN_FI_ENROLLMENT"],"enabled")
        self.assertEqual(
            fields["DATABASE_URL"],
            "postgresql://mnebyvpn_fi_enroll:"+"a"*64+"@127.0.0.1:55433/mnebyvpn_stage"
        )
        self.assertTrue(fields["FI_ENROLL_NODE_PUBLIC_SPKI_FILE"].endswith("fi-node-public.spki"))
        self.assertTrue(fields["AWG_CONTROLLER_SIGNING_KEY_FILE"].startswith("/root/"))

    def test_existing_protected_env_with_numeric_sha256_key_is_idempotent(self):
        import tempfile
        password="b"*64
        serialized="".join(k+"="+v+"\n" for k,v in
                           module.env_fields(password).items()).encode()
        with tempfile.TemporaryDirectory() as temporary:
            location=Path(temporary)/"fi-enrollment.env"
            location.write_bytes(serialized)
            with (
                mock.patch.object(module,"ENV",location),
                mock.patch.object(module,"root_directory"),
                mock.patch.object(module,"protected",return_value=serialized),
            ):
                found,created=module.environment()
                self.assertEqual(found,password)
                self.assertFalse(created)

    def test_refuse_wrong_or_public_database_port(self):
        sample=[{"State":{"Running":True},"HostConfig":{"PortBindings":{
            "5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"55433"}]}}}]
        with mock.patch.object(module,"exec_public",return_value=json.dumps(sample)):
            with self.assertRaises(module.Stop):
                module.canonical_database()
        sample[0]["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"]="127.0.0.1"
        sample[0]["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostPort"]="65432"
        with mock.patch.object(module,"exec_public",return_value=json.dumps(sample)):
            with self.assertRaises(module.Stop):
                module.canonical_database()

    def test_fail_if_existing_role_without_protected_config(self):
        with mock.patch.object(module,"sql",return_value="true") as query:
            with self.assertRaises(module.Stop):
                module.verify_role_and_approve("A"*59,"a"*64,True)
            self.assertEqual(query.call_count,1)

    def test_approval_never_touches_a_different_fi_identity(self):
        approved="A"*59
        queries=[]
        def fake_sql(s):
            queries.append(s)
            if "SELECT EXISTS" in s:return "false"
            return "approved|fi.mnebyvpn.site|"+approved+"|true"
        with mock.patch.object(module,"sql",side_effect=fake_sql):
            module.verify_role_and_approve(approved,"a"*64,True)
        statement=queries[1]
        self.assertIn("WHERE node_id='fi-test-01'",statement)
        self.assertIn("status='planned'",statement)
        self.assertIn("GRANT SELECT,INSERT,UPDATE(consumed_at)",statement)
        self.assertNotIn("DELETE FROM",statement)
        self.assertNotIn("vpn_additional_nodes",statement)
        self.assertNotIn("vpn_awg_clients",statement)

    def test_no_client_service_or_network_change_in_bootstrap(self):
        src=path.read_text()
        self.assertNotIn("systemctl start",src)
        self.assertNotIn("iptables -",src)
        self.assertNotIn("docker restart",src)
        self.assertNotIn("SUBSCRIBERS_PUBLISHED=true",src)
