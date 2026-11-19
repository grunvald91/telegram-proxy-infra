"""Read-only owner SmartDNS audit privacy and fail-closed contract."""
from pathlib import Path
import subprocess
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"mnebydns-owner-permanent-readonly-20261119.py"


class OwnerPermanentDnsReadOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=SCRIPT.read_text(encoding="utf-8")

    def test_script_compiles_and_self_tests(self):
        for cmd in (["python3","-m","py_compile",str(SCRIPT)],
                    ["python3",str(SCRIPT),"--role","runner","--self-test"]):
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_no_bearer_hostname_or_owner_private_fields_logged(self):
        self.assertNotIn("zpfo73bh04ng",self.source)
        self.assertNotIn("token_ciphertext",self.source)
        self.assertNotIn("print(result.stdout)",self.source)
        self.assertNotIn("print(sql)",self.source)
        self.assertIn("OWNER_DOT_AUTHENTICATED_CLIENT_QUERY=NOT_TESTED_NO_BEARER",self.source)
        self.assertIn("OWNER_DOT_CHANGES=NONE",self.source)

    def test_checks_exact_owner_permanent_grant_and_backend(self):
        for term in ("owner_dns_links", "permanent AND video_route='smart_dns'",
                     "revoked_at IS NULL AND expires_at IS NULL",
                     "owner_dns_link_status(text)", "MNEBYDNS_OWNER_LINKS_ENABLED",
                     "MNEBYDNS_PERSONAL_DOT_BIND_IP", "PUBLIC_WILDCARD_TLS",
                     "DE_TO_RU_PRIVATE_TCP", "RU_PRIVATE_PERSONAL_TLS"):
            with self.subTest(term=term):
                self.assertIn(term,self.source)

    def test_no_mutating_commands(self):
        for forbidden in ("UPDATE public.", "INSERT INTO ", "DELETE FROM ",
                          "docker restart", "systemctl restart", "systemctl start",
                          "iptables ", "nft add", "certbot ", "ssh-keyscan"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,self.source)


if __name__=="__main__":
    unittest.main()
