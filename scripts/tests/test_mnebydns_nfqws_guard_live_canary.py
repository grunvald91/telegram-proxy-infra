#!/usr/bin/env python3
"""Offline integrity checks for live generator canary's emergency watchdog."""
import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
FILE=ROOT/"mnebydns_nfqws_guard_live_canary.py"
spec=importlib.util.spec_from_file_location("canary",FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CanarySafety(unittest.TestCase):
    def test_watchdog_compiles_and_only_targets_own_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/"rollback.py"
            peer=pathlib.Path(tmp)/"peer"
            m.watchdog_script(path,peer)
            source=path.read_text()
            compile(source,str(path),"exec")
            self.assertIn("MNEBYDNS_SYNACK_CANARY_PEER_V1",source)
            self.assertIn("delete",source)
            self.assertIn("handle",source)
            self.assertIn("telegram-nfqws-rules",source)
            self.assertNotIn("systemctl restart",source)
            self.assertNotIn("flush ruleset",source)
            self.assertIn(str(peer),source)

    def test_no_default_allowlist_or_global_bypass(self):
        src=FILE.read_text()
        self.assertIn("CONF.exists() or CONF.is_symlink()",src)
        self.assertIn("on-active=85s",src)
        self.assertIn("generator_canary_scope=one_peer_ipv4_synack_only",src)
        self.assertIn("MNEBYDNS_SYNACK_CANARY_FILE",src)
        self.assertIn("nfqws",src)
        self.assertNotIn("ufw disable",src)
        self.assertNotIn("systemctl restart",src)

if __name__=="__main__":
    unittest.main()
