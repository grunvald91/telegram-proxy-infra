"""FI217 production readiness must report blockers without changing services."""
from pathlib import Path
import sys
import unittest
from unittest import mock

NODEKIT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(NODEKIT))
import fi_awg_live_readiness as probe

class FiReadinessTests(unittest.TestCase):
    def test_only_existing_expected_nodes(self):
        self.assertEqual(probe.RU_IP,"188.120.254.223")
        self.assertEqual(probe.FI_IP,"217.11.167.91")
        self.assertEqual(probe.FI_NODE,"fi-test-01")

    def test_no_keys_or_secrets_in_output(self):
        with mock.patch.object(probe,"host"), \
             mock.patch.object(probe,"systemd_state",return_value="inactive"), \
             mock.patch.object(probe,"checked",return_value="false|staged|not_fresh|enrolled|true"), \
             mock.patch.object(probe,"web_configuration",return_value={
                "WEB_FI_AWG_SERVER_PUBLIC_KEY":"absent",
                "WEB_FI_AWG_HEADER_PROTECTION_KEY":"absent",
             }), \
             mock.patch.object(probe.request,"urlopen",side_effect=OSError("offline")):
            data=probe.ru()
            self.assertEqual(data["POOL"],"staged")
            self.assertEqual(data["POOL_PROOF"],"not_fresh")
            self.assertEqual(data["RELEASE"],"false")
            self.assertEqual(data["WEB_AWG_PAGE"],"not_published")
            self.assertNotIn("DATABASE_URL",str(data))

    def test_ambiguous_db_read_is_denied(self):
        with mock.patch.object(probe,"host"), \
             mock.patch.object(probe,"systemd_state",return_value="inactive"), \
             mock.patch.object(probe,"checked",return_value="invalid|abc|fresh|enrolled|true"):
            with self.assertRaises(probe.Blocked):
                probe.ru()

    def test_web_secrets_never_emitted(self):
        with mock.patch.object(probe,"protected_text",return_value=(
            "WEB_FI_AWG_SERVER_PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            "WEB_FI_AWG_HEADER_PROTECTION_KEY=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
            "WEB_FI_AWG_MATERIAL_ENABLED=no\n"
        )):
            data=probe.web_configuration()
            self.assertEqual(data["WEB_FI_AWG_SERVER_PUBLIC_KEY"],"present")
            self.assertEqual(data["WEB_FI_AWG_HEADER_PROTECTION_KEY"],"present")
            self.assertNotIn("BBBB",str(data))

    def test_diagnostic_fields_identify_components_independently(self):
        self.assertEqual(probe.diagnostic_fields("fi",{
            "AWG_SERVICE":"failed","AWG_WATCHDOG":"active","AWG_INTERFACE":"absent",
        }),["FI_AWG_DETAIL_AWG_SERVICE=failed",
            "FI_AWG_DETAIL_AWG_WATCHDOG=active",
            "FI_AWG_DETAIL_AWG_INTERFACE=absent"])
        self.assertEqual(probe.diagnostic_fields("ru",{
            "POOL":"verified","POOL_PROOF":"not_fresh",
        }),["FI_AWG_DETAIL_POOL=verified","FI_AWG_DETAIL_POOL_PROOF=not_fresh"])

    def test_diagnostic_fields_never_echo_unknown_values(self):
        self.assertEqual(probe.diagnostic_fields("fi",{
            "AWG_SERVICE":"secret material","AWG_WATCHDOG":"active",
            "PRIVATE_KEY":"secret material",
        }),["FI_AWG_DETAIL_AWG_SERVICE=unknown",
            "FI_AWG_DETAIL_AWG_WATCHDOG=active",
            "FI_AWG_DETAIL_AWG_INTERFACE=unknown"])

    def test_journal_classification_does_not_emit_raw_lines(self):
        raw="private data abc123\nSystem UTC rollback during offline access\nnodekit_awg_grants_error=GrantError"
        self.assertEqual(probe.journal_categories(raw),["clock_rollback","grant_error"])
        self.assertEqual(probe.journal_categories("unrecognized sensitive content"),[])

    def test_failure_details_are_allowlisted(self):
        done=mock.Mock(returncode=0,stdout="private peer key\nCannot find device awg0")
        with mock.patch.object(probe,"checked",return_value="Result=exit-code\nExecMainCode=1\nExecMainStatus=secret"), \
             mock.patch.object(probe.subprocess,"run",return_value=done) as run:
            result=probe.failure_details(probe.FI_UNIT,"TEST")
        self.assertEqual(result,["TEST_RESULT=exit-code","TEST_EXECMAINCODE=1",
                         "TEST_EXECMAINSTATUS=unknown","TEST_JOURNAL=interface_missing"])
        self.assertEqual(run.call_args.args[0][2],probe.FI_UNIT)

    def test_failure_details_handle_missing_journal(self):
        with mock.patch.object(probe,"checked",side_effect=probe.Blocked), \
             mock.patch.object(probe.subprocess,"run",side_effect=OSError):
            self.assertEqual(probe.failure_details(probe.FI_WATCHDOG,"TEST"),
                             ["TEST_SYSTEMD=unavailable","TEST_JOURNAL=unavailable"])

    def test_stop_timeline_preserves_order_without_private_messages(self):
        import json
        rows=[
            {"UNIT":probe.FI_UNIT,"__REALTIME_TIMESTAMP":"1795752002000000","MESSAGE":"Control process exited, code=exited, status=1/FAILURE"},
            {"UNIT":probe.FI_WATCHDOG,"__REALTIME_TIMESTAMP":"1795752001000000","MESSAGE":"Stopping watchdog with private context"},
            {"UNIT":probe.FI_EGRESS,"__REALTIME_TIMESTAMP":"1795752000000000","MESSAGE":"Stopping egress"},
            {"UNIT":"other.service","__REALTIME_TIMESTAMP":"1795752001000000","MESSAGE":"Stopping other service"},
        ]
        self.assertEqual(probe.stop_timeline(chr(10).join(map(json.dumps,rows))),
            ["1795752000:egress:stopping","1795752001:watchdog:stopping","1795752002:awg:control_exit"])

    def test_stop_timeline_rejects_untrusted_fields(self):
        import json
        rows=[{"UNIT":probe.FI_UNIT,"__REALTIME_TIMESTAMP":"private","MESSAGE":"Stopping something"},
              {"UNIT":probe.FI_UNIT,"__REALTIME_TIMESTAMP":"1795752001000000","MESSAGE":["private"]},
              {"UNIT":probe.FI_UNIT,"__REALTIME_TIMESTAMP":"1795752001000000","MESSAGE":"private context"}]
        self.assertEqual(probe.stop_timeline(chr(10).join(map(json.dumps,rows))),[])

    def test_readonly_source_and_workflow_contract(self):
        src=(NODEKIT/"fi_awg_live_readiness.py").read_text()
        workflow=(NODEKIT.parent/".github/workflows/fi-awg-live-readiness.yml").read_text()
        for operation in (
            "systemctl start","systemctl enable","systemctl restart",
            "UPDATE public.","INSERT INTO","DELETE FROM","DROP TABLE",
            "docker run","docker stop","--mode grant","--mode apply"
        ):
            self.assertNotIn(operation,src)
        self.assertIn("StrictHostKeyChecking yes",workflow)
        self.assertIn("FI_AWG_CUSTOMER_TECHNICAL_GATES=",workflow)
        self.assertIn("github.event_name != 'pull_request'",workflow)
        self.assertIn("cancel-in-progress: false",workflow)

if __name__=="__main__":
    unittest.main()
