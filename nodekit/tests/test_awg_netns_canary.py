import base64
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import awg_netns_canary as m

PRIVATE=base64.b64encode(bytes(range(32))).decode()
PUBLIC=base64.b64encode(bytes(range(32,64))).decode()
HEADER=base64.b64encode(bytes([123]*32)).decode()


class TestNetnsAwgCanary(unittest.TestCase):
    def test_client_config_is_awg_31_not_plain_wireguard(self):
        result=m.make_client_config(PRIVATE,PUBLIC,HEADER)
        self.assertIn('HeaderProtectionKey = '+HEADER,result)
        self.assertIn('RandomTrailers = on',result)
        self.assertIn('S1 = 16',result)
        self.assertIn('S4 = 16',result)
        self.assertIn('H1 = 1',result)
        self.assertIn('H4 = 4',result)
        self.assertIn('AllowedIPs = 10.73.91.1/32',result)
        self.assertIn('Endpoint = 172.31.254.1:51821',result)
        self.assertIn('Address = 10.73.91.2/24',result)
        self.assertNotIn('PostUp',result)
        self.assertNotIn('iptables',result)

    def test_rejects_bad_private_or_server_keys(self):
        for values in [
            ('bad',PUBLIC,HEADER),
            (PRIVATE,'bad',HEADER),
            (PRIVATE,PUBLIC,'bad'),
        ]:
            with self.subTest(values=values),self.assertRaises(m.NetnsCanaryError):
                m.make_client_config(*values)

    def test_test_only_port_and_interfaces(self):
        self.assertEqual(m.NETNS,'mneby-awg-canary')
        self.assertEqual(m.VETH_HOST,'nkitawg0')
        self.assertEqual(m.TEST_IP,'10.73.91.2')

    def test_refuses_active_awg_or_watchdog_even_in_own_node(self):
        with patch.object(m.os,'geteuid',return_value=0),\
             patch.object(m,'validate',return_value={}),\
             patch.object(m,'safe_manifest',return_value={
                 'advertise_host':'fi.mnebyvpn.site',
                 'registration_enabled':False,
                 'activation_enabled':False,
             }),\
             patch.object(m,'active_unit',return_value=True):
            with self.assertRaises(m.NetnsCanaryError):
                m.cli_preflight(pathlib.Path('/tmp/fi-test-01'),'fi.mnebyvpn.site')


if __name__=='__main__':
    unittest.main()
