#!/usr/bin/env python3
"""Offline tests for one-peer temporary queue-210 bypass. No nft privileges."""
import importlib.util
import pathlib
import tempfile
from unittest import TestCase, main

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "mnebydns_instagram_queue210_synack_ab.py"
spec = importlib.util.spec_from_file_location("ig_ab", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NORMAL = """
table inet telegram_nfqws {
    chain post {
        type filter hook postrouting priority srcnat; policy accept;
        meta mark & 0x00000001 == 0x00000001 tcp sport 443 queue flags bypass to 210 # handle 24
    }
}
"""


class Queue210BypassTests(TestCase):
    def test_requires_expected_live_chain(self):
        mod.ensure_preflight(NORMAL)
        for bad in (
            NORMAL.replace("policy accept", "policy drop"),
            NORMAL.replace("hook postrouting", "hook output"),
            NORMAL.replace("flags bypass", "flags fanout"),
            NORMAL.replace("to 210", "to 211"),
            NORMAL.replace("meta mark & ", "meta abc & "),
            NORMAL.replace("tcp sport 443", "tcp dport 443"),
            NORMAL.replace("    chain post", "    chain wrong"),
            NORMAL.replace("    chain post", "    chain post") + 
                '  tcp sport 443 meta mark 1 queue flags bypass to 210 # handle 25\n',
            NORMAL + '  comment "MNEBY_IG_SYNACK_AB_20261110"\n',
        ):
            with self.subTest(case=bad[-110:]):
                with self.assertRaises(RuntimeError):
                    mod.ensure_preflight(bad)

    def test_rule_handle_and_counter_are_bound_to_unique_comment(self):
        after = NORMAL.replace("        meta mark", '''        ip saddr 188.120.254.223 ip daddr 203.0.113.11 tcp sport 443 tcp flags & (syn | ack) == (syn | ack) counter packets 3 bytes 180 return comment "MNEBY_IG_SYNACK_AB_202611101122" # handle 88
        meta mark''')
        tag = "MNEBY_IG_SYNACK_AB_202611101122"
        self.assertEqual(mod.tagged_handles(after, tag), [88])
        self.assertEqual(mod.counts(after, tag), (3, 180))
        self.assertEqual(mod.tagged_handles(after, "OTHER_TEST"), [])
        self.assertIsNone(mod.counts(after, "OTHER_TEST"))

    def test_rollback_script_is_self_contained_and_compilable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "rollback.py"
            mod.write_watchdog(path, "MNEBY_IG_SYNACK_AB_202611101122")
            code = path.read_text()
            compile(code, str(path), "exec")
            self.assertIn("nft", code)
            self.assertIn("delete", code)
            self.assertIn("handle", code)
            self.assertIn("telegram_nfqws", code)
            self.assertIn('202611101122', code)
            self.assertTrue(path.stat().st_mode & 0o100)

    def test_no_global_firewall_mutations_or_service_restards(self):
        code = SOURCE.read_text()
        self.assertIn("ip saddr {SERVER} ip daddr {peer}", code)
        self.assertIn("tcp sport 443 tcp flags & (syn | ack)", code)
        self.assertIn("systemd-run", code)
        self.assertLess(code.index('shell(["nft", "--check", "-f", "-"]'),
                        code.index('shell(["nft", "-f", "-"]'))
        for forbidden in ("flush ruleset", "delete table", "ufw disable",
                          "systemctl restart", "killall nfqws"):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    main()
