"""Review gates for the RU188 least-privilege AWG DB credential stage."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

path=Path(__file__).resolve().parents[1]/"ru_awg_db_stage.py"
spec=importlib.util.spec_from_file_location("ru_awg_db_stage",path)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

class AwgDbStageTests(unittest.TestCase):
    def test_database_uri_and_worker_config_are_pinned_and_off(self):
        p=stage.fields("a"*64)
        self.assertEqual(p["MNEBYVPN_AWG_DELIVERY_WORKER"],"disabled")
        self.assertEqual(p["DATABASE_URL"],
                         "postgresql://mnebyvpn_awg_delivery:"+
                         "a"*64+"@127.0.0.1:55433/mnebyvpn_stage")
        self.assertEqual(p["AWG_CONTROLLER_SIGNING_KEY_FILE"],
                         "/root/mnebyvpn-controller/controller-signing-key.pem")
        self.assertEqual(p["AWG_CONTROLLER_SSH_IDENTITY_FILE"],
                         "/root/mnebyvpn-controller/awg-delivery-ssh")
        self.assertEqual(p["AWG_CONTROLLER_SSH_KNOWN_HOSTS_FILE"],
                         "/root/mnebyvpn-controller/awg-delivery-known_hosts")

    def test_preflight_fails_wrong_host(self):
        with mock.patch.object(stage,"on_ru",return_value=False):
            with self.assertRaisesRegex(stage.Halt,"not_existing_ru188"):
                stage.preflight()

    def test_preflight_rejects_unpinned_signer(self):
        with (mock.patch.object(stage,"on_ru",return_value=True),
              mock.patch.object(stage,"owned_dir"),
              mock.patch.object(stage,"read",return_value=b"untrusted")):
            with self.assertRaisesRegex(stage.Halt,"controller_signature_pin_invalid"):
                stage.preflight()

    def test_no_billing_mutation_or_public_release_from_stage(self):
        source=path.read_text()
        for unsafe in (
          "UPDATE public.entitlements", "DELETE FROM public.entitlements",
          "GRANT UPDATE ON public.entitlements",
          "GRANT UPDATE ON public.vpn_release_flags",
          "systemctl start", "systemctl enable",
          "vpn_release_flags SET enabled=true",
          "CREATE TRIGGER", "ALTER TABLE entitlements"
        ):
            self.assertNotIn(unsafe,source)
        self.assertIn("BILLING_WRITES=false",source)
        self.assertIn('if active:fail("refuse_active_delivery_worker")',source)
        self.assertIn("existing_env()",source)
        self.assertIn("AWG_DB_ENV=protected",source)
        self.assertIn("GRANT SELECT ON public.entitlements",source)
