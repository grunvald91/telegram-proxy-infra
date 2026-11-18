import importlib.util
from pathlib import Path
import unittest
import socket
import struct
import tempfile
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'mnebydns_personal_private_probe_20261118.py'
spec=importlib.util.spec_from_file_location('private_probe',SOURCE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PrivateProbeTests(unittest.TestCase):
    def test_both_ru_backend_and_public_de_sni_receive_authorized_queries(self):
        obj={'label':'monitorabc12','id':'5bd8b96a-7549-42c7-ae21-123d9a0df12d',
             'request_key':'internal-monitor-123'}
        private=('10.0.0.2',8858)
        public=('dns.mnebyvpn.site',853)
        def answer(label,domain,endpoint):
            return ['198.51.100.21']
        with patch.object(mod,'status',return_value='ALLOWED_SMART_DNS'), \
             patch.object(mod,'endpoints',return_value=(private,public,'198.51.100.21')), \
             patch.object(mod,'dns_query',side_effect=answer) as q:
            mod.verify_profile(obj)
            self.assertEqual(q.call_count,6)
            sent=[call.args[2] for call in q.call_args_list]
            self.assertEqual(sent,[private]*3+[public]*3)

    def test_inactive_personal_profile_never_probed_or_renewed(self):
        obj={'label':'monitorabc12'}
        with patch.object(mod,'status',return_value='DENY_INACTIVE'), \
             patch.object(mod,'dns_query') as q:
            with self.assertRaises(RuntimeError):
                mod.verify_profile(obj)
            q.assert_not_called()

    def test_route_drift_is_rejected(self):
        obj={'label':'monitorabc12'}
        def bad(label,domain,endpoint):
            return ['173.194.188.102'] if domain==mod.DOMAIN else ['198.51.100.21']  # Wrong for smart_dns video
        with patch.object(mod,'status',return_value='ALLOWED'), \
             patch.object(mod,'endpoints',return_value=(('10.0.0.2',8858),('dns.mnebyvpn.site',853),'198.51.100.21')), \
             patch.object(mod,'dns_query',side_effect=bad):
            with self.assertRaisesRegex(RuntimeError,'ROUTE_DRIFT'):
                mod.verify_profile(obj)

    def test_bounded_dns_answer_parser(self):
        question=b'\x07youtube\x03com\x00'+struct.pack('!HH',1,1)
        header=struct.pack('!HHHHHH',1234,0x8180,1,1,0,0)
        rr=b'\xc0\x0c'+struct.pack('!HHIH',1,1,20,4)+socket.inet_aton('89.125.90.101')
        response=header+question+rr
        self.assertEqual(mod._answer_ipv4(response),['89.125.90.101'])
        with self.assertRaises(RuntimeError):
            mod._answer_ipv4(response[:-1])
        with self.assertRaises(RuntimeError):
            mod._answer_ipv4(response[:4])

    def test_renewal_requires_exactly_one_record(self):
        obj={'label':'monitorabc12','id':'5bd8b96a-7549-42c7-ae21-123d9a0df12d',
             'request_key':'internal-monitor-123'}
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'state.json'
            state.write_text('{"test":true}')
            with patch.object(mod,'STATE',state), \
                 patch.object(mod,'read_state',return_value=obj), \
                 patch.object(mod,'verify_profile'), \
                 patch.object(mod,'db',return_value='0'), \
                 patch.object(mod.os,'geteuid',return_value=0):
                with self.assertRaisesRegex(RuntimeError,'ROW_COUNT_INVALID'):
                    mod.stage()

    def test_topology_is_read_from_live_service_not_hardcoded(self):
        from unittest.mock import Mock
        env=['MNEBYDNS_PERSONAL_DOT_BIND_IP=10.0.0.2',
             'MNEBYDNS_PERSONAL_DOT_PORT=8858']
        result=Mock(returncode=0,stdout=__import__('json').dumps(env))
        with patch.object(mod.subprocess,'run',return_value=result), \
             patch.object(mod.socket,'gethostbyname',return_value='8.8.8.8'):
            self.assertEqual(mod.endpoints(),(('10.0.0.2',8858),
                             ('dns.mnebyvpn.site',853),'8.8.8.8'))

    def test_topology_refuses_invalid_bind(self):
        from unittest.mock import Mock
        result=Mock(returncode=0,stdout='["MNEBYDNS_PERSONAL_DOT_BIND_IP=8.8.8.8","MNEBYDNS_PERSONAL_DOT_PORT=8858"]')
        with patch.object(mod.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(RuntimeError,'BIND_UNSAFE'):
                mod.endpoints()

    def test_unspecified_bind_rejected(self):
        from unittest.mock import Mock
        result=Mock(returncode=0,stdout='["MNEBYDNS_PERSONAL_DOT_BIND_IP=0.0.0.0","MNEBYDNS_PERSONAL_DOT_PORT=8858"]')
        with patch.object(mod.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(RuntimeError,'BIND_UNSAFE'):
                mod.endpoints()

    def test_revocation_requires_confirmed_single_row(self):
        obj={'id':'5bd8b96a-7549-42c7-ae21-123d9a0df12d',
             'request_key':'internal-monitor-123'}
        with patch.object(mod,'db',return_value='0'):
            with self.assertRaisesRegex(RuntimeError,'REVOKE_ROW_COUNT_INVALID'):
                mod.delete_own_row(obj)
        with patch.object(mod,'db',return_value='1'):
            mod.delete_own_row(obj)

    def test_revoke_reenables_monitor_if_database_delete_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            timer=root/'monitor.timer'
            unit=root/'monitor.service'
            state=root/'state.json'
            timer.write_text('Unit=mnebydns-personal-private-probe.service\n')
            unit.write_text('ExecStart=/usr/local/sbin/mnebydns-personal-private-probe\n')
            state.write_text('{}')
            mock_data={'id':'5bd8b96a-7549-42c7-ae21-123d9a0df12d',
                       'request_key':'internal-monitor-123'}
            with patch.object(mod,'TIMER',timer), \
                 patch.object(mod,'SERVICE',unit), \
                 patch.object(mod,'STATE',state), \
                 patch.object(mod,'read_state',return_value=mock_data), \
                 patch.object(mod,'delete_own_row',side_effect=RuntimeError('db offline')), \
                 patch.object(mod.subprocess,'run') as command, \
                 patch.object(mod.os,'geteuid',return_value=0):
                with self.assertRaisesRegex(RuntimeError,'db offline'):
                    mod.revoke()
                self.assertTrue(state.exists())
                self.assertEqual(command.call_count,2)
                self.assertEqual(command.call_args_list[0].args[0][:3],
                                 ['systemctl','disable','--now'])
                self.assertEqual(command.call_args_list[1].args[0][:3],
                                 ['systemctl','enable','--now'])

    def test_service_monitor_is_non_permanent_and_has_short_lease(self):
        code=SOURCE.read_text()
        self.assertIn("'smart_dns'",code)
        self.assertNotIn("repeat('x',54)",code)
        self.assertIn('encrypt_for_owner_link(data)',code)
        self.assertNotIn('89.125.90.101',code)
        self.assertNotIn('188.120.254.223',code)
        self.assertIn("permanent,expires_at,video_route",code)
        self.assertIn("clock_timestamp()+interval '30 days'",code)
        self.assertNotIn('print(data',code)
        self.assertNotIn('print(label',code)

if __name__=='__main__':unittest.main()
