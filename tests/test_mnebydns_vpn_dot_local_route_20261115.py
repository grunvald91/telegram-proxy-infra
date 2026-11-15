#!/usr/bin/env python3
"""Offline guardrail checks only; never accesses a server or modifies system state."""
import pathlib
import re
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "mnebydns-vpn-dot-local-route-20261115.sh"
SOURCE=SCRIPT.read_text()

class VPNLocalDNSRoute(unittest.TestCase):
    def test_matches_only_dedicated_nonroot_vpn_uid(self):
        self.assertIn("OWNER=mnebyvpn-xray", SOURCE)
        self.assertIn('uid="$(id -u "$OWNER")"', SOURCE)
        self.assertIn('test "$uid" != 0', SOURCE)
        self.assertIn('--uid-owner "$uid"', SOURCE)

    def test_matches_only_own_dot_endpoint(self):
        self.assertIn("IP=89.125.90.101", SOURCE)
        self.assertIn('--dport 853 -m owner --uid-owner', SOURCE)
        self.assertIn('-d "$IP"/32', SOURCE)
        self.assertIn('ROUTER_PORT=8854', SOURCE)
        self.assertIn('REDIRECT --to-ports "$ROUTER_PORT"', SOURCE)

    def test_preserves_original_personal_router_and_legacy(self):
        for needle in (
            "default 89.125.90.101:853;",
            "10.66.77.2:8856;",
            "listen 0.0.0.0:8854;",
            "mnebydns-personal-sni-stream.service",
            "mnebydns-personal-sni-redirect.service",
            "mnebyvpn-vpn-provisioner.service",
        ):
            self.assertIn(needle,SOURCE)

    def test_auto_revert_and_idempotence_guards(self):
        self.assertIn("--on-active=4m",SOURCE)
        self.assertIn('if test -f "$MARK" || present; then',SOURCE)
        self.assertIn('iptables -w -t nat -D OUTPUT',SOURCE)
        self.assertIn('iptables -w -t nat -I OUTPUT 1',SOURCE)
        self.assertIn('trap \'rollback\' ERR',SOURCE)
        self.assertIn('probe aaaaaaaaaaaa.dns.mnebyvpn.site',SOURCE)
        self.assertIn('probe dns.mnebyvpn.site',SOURCE)

    def test_never_restarts_services_or_touches_keys(self):
        for needle in ("systemctl restart","wg set","wg-quick down",
                       "xray-canary.json","Corefile","iptables -F","iptables -X","ip6tables",
                       "--dport 443","--dport 2053","iptables -t nat -F"):
            self.assertNotIn(needle,SOURCE)

if __name__=="__main__":
    unittest.main(verbosity=2)
