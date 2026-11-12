#!/usr/bin/env python3
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
BASH = (ROOT / "mnebydns-synack-window-canary.sh").read_text()


class GuardrailsTests(TestCase):
    def test_dedicated_port_only_and_no_production_dns_changes(self):
        self.assertIn("PORT=18443", BASH)
        self.assertIn("SERVER=188.120.254.223", BASH)
        self.assertNotIn("PORT=443\n", BASH)
        self.assertNotIn("systemctl restart", BASH)
        self.assertNotIn("nginx -s reload", BASH)

    def test_watchdog_precedes_rule_and_uses_no_repo_file(self):
        self.assertIn("systemd-run --quiet --collect", BASH)
        self.assertLess(BASH.index("systemd-run --quiet --collect"),
                        BASH.index("iptables -w -t mangle -I OUTPUT 1"))
        self.assertIn("MNEBYDNS_ROLLBACK", BASH)
        self.assertIn("flock -n 9", BASH)

    def test_waits_for_failopen_queue_ready_before_installing(self):
        self.assertIn("queue.ready", BASH)
        self.assertLess(BASH.index('[[ "$ready" == 1 ]]'),
                        BASH.index("iptables -w -t mangle -I OUTPUT 1"))


if __name__ == "__main__":
    main()
