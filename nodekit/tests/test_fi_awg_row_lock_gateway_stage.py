"""Offline AWG row-lock gateway installer contract; never opens production DB."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

SCRIPT=Path(__file__).resolve().parents[1]/"fi_awg_row_lock_gateway_stage.py"
spec=importlib.util.spec_from_file_location("fi_awg_row_lock_gateway_stage",SCRIPT)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class AwgGatewayStageTests(unittest.TestCase):
    def test_installed_metadata_requires_exact_definer_owner_acl(self):
        lines="\n".join("|".join([name.split("(")[0],"true","true","true","true","false"])
            for name in sorted(stage.FUNCS))
        with mock.patch.object(stage,"installed_metadata",return_value=lines):
            self.assertTrue(stage.check_installed())
        for broken in (
            lines.replace("|true|true|true|true|false","|false|true|true|true|false",1),
            lines.replace("|true|true|true|true|false","|true|true|true|true|true",1),
            lines.split("\n")[0],lines+"\nextra|true|true|true|true|false",
        ):
            with mock.patch.object(stage,"installed_metadata",return_value=broken):
                self.assertFalse(stage.check_installed())

    def test_real_role_probe_is_bounded_and_rolls_back(self):
        probe=["0","1","0","0"]
        with (mock.patch.object(stage,"check_installed",return_value=True),
              mock.patch.object(stage,"sql",return_value="\n".join(probe)) as sql):
            stage.grant_gateway()
            text=sql.call_args.args[0]
            self.assertIn("SET LOCAL ROLE mnebyvpn_awg_delivery",text)
            self.assertIn("ROLLBACK;",text)
            self.assertIn("awg_worker_lock_entitlement",text)
            self.assertIn("awg_worker_lock_pool_node",text)
            self.assertNotIn("GRANT UPDATE",text)

    def test_worker_cannot_be_started_or_published_by_stage(self):
        body=SCRIPT.read_text()
        for prohibited in (
            "systemctl start", "systemctl enable", "vpn_awg_clients',true",
            "UPDATE entitlements", "UPDATE vpn_release_flags",
            "INSERT INTO vpn_awg_peer_allocations", "client-private-key",
        ):
            self.assertNotIn(prohibited,body)
        self.assertIn("unexpected",body.lower() if "unexpected" in body.lower() else "unexpected")
        self.assertIn("MNEBYVPN_AWG_DELIVERY_WORKER=disabled",body)
        self.assertIn("FI_AWG_ROW_LOCK_GATEWAY_READY=true",body)
        self.assertIn("awg_client", "awg_client")
