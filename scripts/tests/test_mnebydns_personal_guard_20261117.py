import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SOURCE=pathlib.Path(__file__).resolve().parents[1]/'mnebydns_personal_guard_20261117.py'
spec=importlib.util.spec_from_file_location('personal_guard',SOURCE)
watch=importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)

class WatchTests(unittest.TestCase):
    def test_route_only_existing_personal_map(self):
        with tempfile.TemporaryDirectory() as d:
            f=pathlib.Path(d,'nginx.conf')
            f.write_text('stream {\n  map $ssl_preread_server_name $personal_dot_target {\n'
                         '    "~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.0.0.2:8858;\n'
                         '    default 127.0.0.1:853;\n  }\n}')
            with patch.object(watch,'CONF',f):
                self.assertEqual(watch.route(),('10.0.0.2',8858))
            f.write_text('stream { default 127.0.0.1:853; }')
            with patch.object(watch,'CONF',f):
                with self.assertRaises(RuntimeError):watch.route()

    def test_candidates_never_mine_customer_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            old=pathlib.Path(d,'watch')
            old.write_text("'probe1234567.dns.mnebyvpn.site'")
            profile=pathlib.Path(d,'profile')
            with patch.object(watch,'PROFILE',profile), patch.object(watch,'WATCH',old):
                self.assertEqual(watch.candidate_names(),[])
                profile.write_text('probe1234567.dns.mnebyvpn.site')
                self.assertEqual(watch.candidate_names(),['probe1234567.dns.mnebyvpn.site'])

    def test_check_requires_dns_answer_at_both_hops(self):
        with patch.object(watch,'route',return_value=('10.0.0.2',8858)), \
             patch.object(watch.PROFILE,'exists',return_value=True), \
             patch.object(watch,'profile_name',return_value='probe1234567.dns.mnebyvpn.site'), \
             patch.object(watch,'probe',side_effect=[(0,1)]*6+[(5,0)]) as p:
            watch.check()
            self.assertEqual(p.call_count,7)
        with patch.object(watch,'route',return_value=('10.0.0.2',8858)), \
             patch.object(watch.PROFILE,'exists',return_value=True), \
             patch.object(watch,'profile_name',return_value='probe1234567.dns.mnebyvpn.site'), \
             patch.object(watch,'probe',return_value=(3,0)):
            with self.assertRaises(RuntimeError):watch.check()

    def test_missing_service_profile_is_transport_only(self):
        with patch.object(watch,'route',return_value=('10.0.0.2',8858)), \
             patch.object(watch.PROFILE,'exists',return_value=False), \
             patch.object(watch,'tls_reachable') as tls, \
             patch.object(watch,'probe',return_value=(5,0)) as p:
            watch.check()
            self.assertEqual(tls.call_count,2)
            self.assertEqual(p.call_count,1)

if __name__=='__main__':unittest.main()
