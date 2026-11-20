"""Customer AWG public website rollout: scoped flags, exact keys and rollback."""
import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_awg_customer_web_release as m

PUB=base64.b64encode(bytes(range(1,33))).decode()
HEADER=base64.b64encode(bytes(range(2,34))).decode()
ENV=(b"MNEBYVPN_ENV=production\nWEB_BASE_URL=https://mnebyvpn.site\n"
     b"WEB_EMAIL_LOGIN_ENABLED=yes\nWEB_RELEASE_APPROVED=yes\n"
     b"WEB_CHECKOUT_ENABLED=1\nWEB_TRIAL_ENABLED=yes\n"
     b"WEB_FI_AWG_REGISTRATION_ENABLED=no\n")

class PublicReleaseTests(unittest.TestCase):
    def test_update_is_scoped_idempotent_and_preserves_commercial_flags(self):
        data=m.updated_env(ENV,PUB,HEADER)
        lines,flags=m.read_env(data)
        self.assertEqual(flags["WEB_FI_AWG_REGISTRATION_ENABLED"],"yes")
        self.assertEqual(flags["WEB_FI_AWG_MATERIAL_ENABLED"],"yes")
        self.assertEqual(flags["WEB_FI_AWG_SERVER_PUBLIC_KEY"],PUB)
        self.assertEqual(flags["WEB_FI_AWG_HEADER_PROTECTION_KEY"],HEADER)
        self.assertEqual(flags["WEB_NETWORK_PROVISIONING_VERIFIED"],"yes")
        self.assertEqual(flags["WEB_CHECKOUT_ENABLED"],"1")
        self.assertEqual(flags["WEB_TRIAL_ENABLED"],"yes")
        self.assertEqual(m.updated_env(data,PUB,HEADER),data)

    def test_rejects_duplicate_environment_key(self):
        with self.assertRaises(m.Blocked):
            m.updated_env(ENV+b"WEB_EMAIL_LOGIN_ENABLED=yes\n",PUB,HEADER)

    def test_rejects_untrusted_server_public_key(self):
        with patch.object(m,"trusted",return_value=json.dumps({"nodeId":"fi-test-01","hostname":"fi.mnebyvpn.site","port":51821,"clientIp":"10.73.91.253","serverPublicKey":"bad","headerKey":HEADER}).encode()):
            with self.assertRaises(m.Blocked):
                m.material(Path("/unused"))
        self.assertFalse(m.valid_key("bad"))
        self.assertFalse(m.valid_key(base64.b64encode(bytes(32)).decode()))
        self.assertTrue(m.valid_key(PUB))

    def test_release_flag_requires_fresh_e2e_and_exact_pool(self):
        with patch.object(m,"sql",return_value="") as sql:
            m.release_flag(True,PUB)
            self.assertEqual(sql.call_count,1)
            statement=sql.call_args.args[0]
            self.assertIn("verified_at>clock_timestamp()-interval '1 hour'",statement)
            self.assertIn("external_e2e_proof_sha256 ~",statement)
            self.assertIn("GET DIAGNOSTICS n=ROW_COUNT",statement)
            self.assertIn("IF n!=1",statement)
            self.assertIn("enabled=true",statement)

    def test_release_does_not_touch_other_production_services(self):
        source=Path(m.__file__).read_text()
        for forbidden in ("systemctl stop nginx","iptables","awg-quick","docker system prune",
                          "DROP TABLE","webhook secret", "node-private.pk8"):
            self.assertNotIn(forbidden,source)
        self.assertIn('launch(image,CANARY,port,candidate,old,temporary=True)',source)
        self.assertIn('release_flag(False,pub)',source)
        self.assertIn('launch(image,WEB_NAME,8792,WEB_ENV,old,temporary=False)',source)

if __name__=="__main__":unittest.main()
