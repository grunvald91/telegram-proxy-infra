#!/usr/bin/env python3
"""Offline guards for v10 test. No production network, sysctl, or nft writes."""
import importlib.util
import inspect
from pathlib import Path
import tempfile
import subprocess
from unittest.mock import patch
import unittest

ROOT=Path(__file__).resolve().parents[1]

def candidate():
    p=ROOT/"mnebydns_iglite_wifi_multi_meta_v10_w20.py"
    spec=importlib.util.spec_from_file_location("v10_readonly",p)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class V10Window20Review(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v=candidate()

    def test_exact_hosts_and_boundaries(self):
        v=self.v
        self.assertEqual(len(v.HOSTS),11)
        self.assertEqual(len(set(v.HOSTS)),11)
        self.assertIn("iglite-z.instagram.com",v.HOSTS)
        self.assertIn("i.instagram.com",v.HOSTS)
        self.assertEqual(v.TEST_WINDOW,20)
        self.assertEqual(v.FIRST_CLIENT_PACKETS,16)
        self.assertEqual(v.TRIAL_SECONDS,900)
        self.assertEqual(v.WATCHDOG_SECONDS,1200)

    def test_nft_ack_window_and_mark_have_same_per_flow_cutoff(self):
        rules=self.v.nft_rules()
        self.assertEqual(rules.count("ct original packets < 16"),2)
        self.assertEqual(rules.count("tcp sport 443"),2)
        self.assertIn("tcp flags & ack == ack counter tcp window set 20",rules)
        self.assertIn("tcp flags & ack == ack meta mark set meta mark | 0x40000000",rules)
        self.assertNotIn("flush ruleset",rules)
        self.assertNotIn("delete table",rules)
        self.assertIn('oifname "eth0"',rules)

    def test_baseline_requires_ws_on_prior_to_any_change(self):
        src=inspect.getsource(self.v.baseline)
        self.assertIn('WSFILE.read_text().strip() != "1"',src)
        self.assertIn("Prior rollback timer active",src)
        self.assertIn("Live baseline diverged from stable checkpoint",src)

    def test_restore_kernel_and_original_live_files(self):
        src=inspect.getsource(self.v.rollback)
        self.assertIn("tcp_window_scaling.original",src)
        self.assertIn("net.ipv4.tcp_window_scaling=",src)
        self.assertIn("WSFILE.read_text().strip() == original_ws",src)
        self.assertIn("NGINX.read_bytes()",src)
        self.assertIn("CORE.read_bytes()",src)

    def test_guarded_watchdog_before_temporary_ws_change(self):
        src=inspect.getsource(self.v.live)
        self.assertLess(src.index('write_exclusive(ROOT / "tcp_window_scaling.original"'),
                        src.index('command(["systemd-run"'))
        self.assertLess(src.index('command(["systemd-run"'),
                        src.index('command(["sysctl", "-w", "net.ipv4.tcp_window_scaling=0"]'))
        self.assertIn("remaining_watchdog < TRIAL_SECONDS + MIN_ROLLBACK_MARGIN",src)
        self.assertIn("finally:\n        rollback()",src)

    def test_rollback_does_not_claim_success_while_dot_inactive(self):
        v=self.v
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"state"
            root.mkdir()
            live_nginx=Path(td)/"nginx.conf"
            live_core=Path(td)/"Corefile"
            live_ws=Path(td)/"tcp_window_scaling"
            for name,data in (
                ("nginx.original",b"nginx-stable"),
                ("nginx.candidate",b"nginx-test"),
                ("core.original",b"core-stable"),
                ("core.candidate",b"core-test"),
                ("tcp_window_scaling.original",b"1\n"),
            ):
                (root/name).write_bytes(data)
            live_nginx.write_bytes(b"nginx-stable")
            live_core.write_bytes(b"core-stable")
            live_ws.write_bytes(b"1\n")
            state={"dot":False,"restart_count":0}
            def fake_command(argv,**kwargs):
                if argv[:4]==["nft","list","table","inet"]:
                    return subprocess.CompletedProcess(argv,1)
                if argv[:4]==["systemctl","is-active","--quiet","mnebydns-dot.service"]:
                    return subprocess.CompletedProcess(argv,0 if state["dot"] else 1)
                if argv[:3]==["systemctl","restart","mnebydns-dot.service"]:
                    state["dot"]=True
                    state["restart_count"]+=1
                return subprocess.CompletedProcess(argv,0)
            with (patch.object(v,"ROOT",root),
                  patch.object(v,"NGINX",live_nginx),
                  patch.object(v,"CORE",live_core),
                  patch.object(v,"WSFILE",live_ws),
                  patch.object(v,"command",side_effect=fake_command)):
                v.rollback()
            self.assertEqual(state["restart_count"],1)
            self.assertTrue(state["dot"])

    def test_live_workflow_is_disabled_until_reboot_safe_restore_exists(self):
        workflow=(ROOT.parent / ".github/workflows/mnebydns-iglite-wifi-v10-onrequest.yml").read_text()
        self.assertEqual(workflow.count("if: ${{ false }}"),2)
        self.assertIn("REVIEW BLOCKER: no persistent reboot-safe recovery unit yet",workflow)
        self.assertIn("timeout-minutes: 18",workflow)
        self.assertIn("for attempt in range(500)",workflow)

    def test_observer_reports_not_phone_attribution(self):
        src=inspect.getsource(self.v.observe_wifi_tcp_headers)
        self.assertIn("iglite_wifi_android_peer_identified=false",src)
        self.assertIn("iglite_wifi_sni_byte_split=NOT_PROVEN_BY_HEADER_CAPTURE",src)
        self.assertIn("iglite_wifi_15min_window=READY",src)
        self.assertIn("outbound_synack_window20",src)
        self.assertIn("iglite_wifi_pcap_persisted=false",src)

if __name__=="__main__":
    unittest.main()
