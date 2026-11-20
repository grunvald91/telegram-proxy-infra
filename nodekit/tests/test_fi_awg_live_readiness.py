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
