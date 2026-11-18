import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'mnebydns_personal_private_probe_20261118.py'
spec=importlib.util.spec_from_file_location('private_probe',SOURCE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PrivateProbeTests(unittest.TestCase):
    def test_both_ru_backend_and_public_de_sni_receive_authorized_queries(self):
        obj={'label':'monitorabc12','id':'5bd8b96a-7549-42c7-ae21-123d9a0df12d',
             'request_key':'internal-monitor-123'}
        with patch.object(mod,'status',return_value='ALLOWED'), \
             patch.object(mod,'dns_query') as q:
            mod.verify_profile(obj)
            self.assertEqual(q.call_count,6)
            sent=[call.args[2] for call in q.call_args_list]
            self.assertEqual(sent,[mod.BACKEND]*3+[mod.PUBLIC]*3)

    def test_inactive_personal_profile_never_probed_or_renewed(self):
        obj={'label':'monitorabc12'}
        with patch.object(mod,'status',return_value='DENY_INACTIVE'), \
             patch.object(mod,'dns_query') as q:
            with self.assertRaises(RuntimeError):
                mod.verify_profile(obj)
            q.assert_not_called()

    def test_service_monitor_is_non_permanent_and_has_short_lease(self):
        code=SOURCE.read_text()
        self.assertIn("'vpn_origin'",code)
        self.assertIn("permanent,expires_at,video_route",code)
        self.assertIn("clock_timestamp()+interval '30 days'",code)
        self.assertNotIn('print(data',code)
        self.assertNotIn('print(label',code)

if __name__=='__main__':unittest.main()
