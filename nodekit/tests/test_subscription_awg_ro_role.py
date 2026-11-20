"""AWG native subscriber's least-privilege reader deployment contract."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/"scripts/mnebyvpn-subscription-read-role.sh"
WORKFLOW=ROOT/".github/workflows/mnebyvpn-subscription-role-prepare.yml"

class SubscriptionRoleSecurity(unittest.TestCase):
    def test_exact_bash_syntax(self):
        result=subprocess.run(["bash","-n",str(SCRIPT)],
            capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_sql_transaction_and_role_is_select_only(self):
        source=SCRIPT.read_text()
        self.assertIn("BEGIN;\nDO $$",source)
        self.assertTrue("END\n$;\nGRANT CONNECT" in source)
        self.assertIn("END\n$$;\nCOMMIT;",source)
        self.assertIn("REVOKE ALL ON ALL TABLES IN SCHEMA public",source)
        self.assertIn("NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION",source)
        for name in ("vpn_awg_node_pools","vpn_awg_peer_allocations",
                     "vpn_node_enrollment_inventory","vpn_awg_command_outbox",
                     "vpn_release_flags"):
            self.assertIn("public."+name,source)
        self.assertIn("has_column_privilege(",source)
        self.assertIn("'attempts','SELECT'",source)
        self.assertIn("'UPDATE'",source)
        self.assertNotRegex(source,re.compile(r"GRANT (ALL|INSERT|UPDATE|DELETE)\b"))
        self.assertNotIn("ALTER SYSTEM",source)

    def test_no_customer_modification_and_safe_ssh(self):
        flow=WORKFLOW.read_text()
        self.assertIn("  pull_request:",flow)
        self.assertIn("    branches: [main]",flow)
        self.assertIn("needs: offline",flow)
        self.assertIn("github.event_name != 'pull_request'",flow)
        self.assertIn("StrictHostKeyChecking=yes",flow)
        self.assertIn("mnebydns-owner-ssh-known_hosts",flow)
        self.assertNotIn("StrictHostKeyChecking=accept-new",flow)
        self.assertIn("mktemp -d /run/mnebyvpn-subscription-ro.",flow)
        self.assertNotIn("systemctl start",flow)
        self.assertNotIn("vpn_awg_clients',true",flow)
        self.assertNotIn("UPDATE public.vpn_release_flags",flow)

if __name__=="__main__":
    unittest.main()
