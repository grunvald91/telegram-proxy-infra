#!/usr/bin/env python3
"""Offline guardrail tests only. Never reach or modify live RU VPS."""
from pathlib import Path
from unittest import TestCase, main

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT / "mnebydns_instagram_ru_ingress_reach.sh"


class IngressGuardrails(TestCase):
    def test_exact_dedicated_port_and_peer_scope(self):
        data=SCRIPT.read_text()
        self.assertIn('PORT=18443', data)
        self.assertIn('SERVER="188.120.254.223"', data)
        self.assertIn('RULE=(-s "$CLIENT/32" -d "$SERVER"', data)
        self.assertIn('--dport "$PORT"', data)
        self.assertNotIn('iptables -F',data)
        self.assertNotIn('iptables -P',data)
        self.assertNotIn('ufw disable',data)

    def test_watchdog_armed_before_firewall_change(self):
        data=SCRIPT.read_text()
        self.assertIn('systemd-run --quiet --collect',data)
        self.assertLess(data.index('systemd-run --quiet --collect'),
                        data.index('iptables -w -I INPUT 1'))
        self.assertIn('trap cleanup EXIT',data)
        self.assertIn('iptables -w -D INPUT',data)

    def test_no_live_443_or_dns_mutation(self):
        data=SCRIPT.read_text()
        self.assertNotIn('--dport 443',data)
        self.assertNotIn('nginx -s reload',data)
        self.assertNotIn('systemctl restart nginx',data)
        self.assertNotIn('Corefile',data)
        self.assertNotIn('wg0',data)

    def test_bounded_listener_and_rollback(self):
        data=SCRIPT.read_text()
        self.assertIn('--on-active=70s',data)
        self.assertIn('timeout 35s',data)
        self.assertIn('ru_ingress_accepted_external_tcp=true',data)


if __name__=="__main__":
    main()
