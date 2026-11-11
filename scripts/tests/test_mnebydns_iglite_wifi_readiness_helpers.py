#!/usr/bin/env python3
"""Regression for readiness gate: CoreDNS uses escaped regex, not dotted FQDN."""
import pathlib
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from mnebydns_iglite_wifi_readiness_helpers import all_hosts_ready,core_exact_host_ready,nginx_exact_host_ready
from mnebydns_iglite_sni_observer import locate_sni

HOST='iglite-z.instagram.com'
EXACT='match ^iglite\\-z[.]instagram[.]com[.]$'

class ReadyGateChecks(unittest.TestCase):
    def test_regex_config_is_found_even_without_dotted_hostname(self):
        core=''.join('    '+EXACT+'\n' for _ in range(5))
        nginx='      '+HOST+' 57.144.244.32:443;\n'
        self.assertNotIn(HOST,core)
        self.assertTrue(core_exact_host_ready(core,HOST))
        self.assertTrue(nginx_exact_host_ready(nginx,HOST))
        self.assertTrue(all_hosts_ready(core,nginx,[HOST]))
    def test_core_incomplete_is_not_ready(self):
        core=''.join(EXACT+'\n' for _ in range(4))
        self.assertFalse(core_exact_host_ready(core,HOST))
    def test_wrong_nginx_host_is_not_ready(self):
        self.assertFalse(nginx_exact_host_ready('evil.'+HOST+' 57.144.244.32:443;',HOST))
    def test_duplicate_host_list_is_not_ready(self):
        core=EXACT*5
        nginx=HOST+' 57.144.244.32:443;'
        self.assertFalse(all_hosts_ready(core,nginx,[HOST,HOST]))

if __name__=='__main__':unittest.main()
