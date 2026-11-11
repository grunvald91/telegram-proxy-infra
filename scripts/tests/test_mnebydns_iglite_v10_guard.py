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
            (root/"mutation-ready").write_text("armed\\n")
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

    def test_boot_recovery_fixes_persistent_files_and_sysctl_without_service_reload(self):
        v=self.v
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"durable-state"
            root.mkdir()
            (root/"mutation-ready").write_text("armed\n")
            nginx=Path(td)/"nginx"
            core=Path(td)/"Corefile"
            ws=Path(td)/"sysctl"
            for name,data in (
                ("nginx.original",b"nginx-original"),
                ("nginx.candidate",b"nginx-temporary"),
                ("core.original",b"core-original"),
                ("core.candidate",b"core-temporary"),
                ("tcp_window_scaling.original",b"1\n"),
            ):
                (root/name).write_bytes(data)
            nginx.write_bytes(b"nginx-temporary")
            core.write_bytes(b"core-temporary")
            ws.write_bytes(b"0\n")
            calls=[]
            def fake_cmd(argv,**kwargs):
                calls.append(argv)
                if argv[:4]==["nft","list","table","inet"]:
                    return subprocess.CompletedProcess(argv,1)
                if argv[:3]==["sysctl","-w","net.ipv4.tcp_window_scaling=1"]:
                    ws.write_text("1\n")
                if argv[0]=="systemctl":
                    raise AssertionError("Boot recovery must not start/reload services")
                return subprocess.CompletedProcess(argv,0)
            with (patch.object(v,"ROOT",root),
                  patch.object(v,"NGINX",nginx),
                  patch.object(v,"CORE",core),
                  patch.object(v,"WSFILE",ws),
                  patch.object(v,"command",side_effect=fake_cmd)):
                v.rollback(boot=True)
            self.assertEqual(nginx.read_bytes(),b"nginx-original")
            self.assertEqual(core.read_bytes(),b"core-original")
            self.assertEqual(ws.read_text().strip(),"1")
            self.assertTrue(any(cmd[0]=="sysctl" for cmd in calls))
            self.assertFalse(any(cmd[0]=="systemctl" for cmd in calls))

    def test_boot_recovery_no_marker_does_not_touch_server(self):
        v=self.v
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"incomplete-backup"
            root.mkdir()
            with patch.object(v,"ROOT",root), patch.object(v,"command") as actions:
                v.rollback(boot=True)
                actions.assert_not_called()

    def test_persistent_service_is_boot_ordered_and_present(self):
        unit=(ROOT.parent / "ops/mneby-ig-lite-v10-recover.service").read_text()
        self.assertIn("DefaultDependencies=no",unit)
        self.assertIn("After=local-fs.target",unit)
        self.assertIn("RequiresMountsFor=/var/lib/mneby-iglite-wifi-de-20261111-v10 /usr/local/libexec/mneby-iglite-v10",unit)
        self.assertIn("Before=nginx.service mnebydns-dot.service",unit)
        self.assertIn("ConditionPathExists=/var/lib/mneby-iglite-wifi-de-20261111-v10/mutation-ready",unit)
        self.assertIn("boot-rollback",unit)
        self.assertIn("WantedBy=multi-user.target",unit)

    def test_durable_backup_fsync_and_marker_precede_global_sysctl_change(self):
        source=inspect.getsource(self.v.live)
        marker='write_exclusive(ROOT / MUTATION_MARKER'
        self.assertIn("fsync_directory(ROOT)",source)
        self.assertIn("fsync_directory(ROOT.parent)",source)
        self.assertLess(source.index("write_exclusive(ROOT / \"tcp_window_scaling.original\""),
                        source.index(marker))
        self.assertLess(source.index("command([\"systemd-run\""),
                        source.index(marker))
        self.assertLess(source.index(marker),
                        source.index('command(["sysctl", "-w", "net.ipv4.tcp_window_scaling=0"]'))

    def test_v11_marker_triggers_only_route_only_workflow(self):
        workflow=(ROOT.parent / ".github/workflows/mnebydns-iglite-wifi-v10-onrequest.yml").read_text()
        self.assertEqual(workflow.count("if: ${{ true }}"),2)
        self.assertNotIn("if: ${{ false }}",workflow)
        self.assertIn("MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED=YES",workflow)
        self.assertIn("ops/mnebydns-iglite-v11-launch.marker",workflow)
        self.assertNotIn("'ops/mnebydns-iglite-wifi-v10-launch.marker'",workflow)
        self.assertIn("timeout-minutes: 18",workflow)
        self.assertIn("for attempt in range(500)",workflow)
        self.assertIn("/var/lib/mneby-iglite-wifi-de-20261111-v11/ready_epoch",workflow)
        self.assertIn("/usr/local/libexec/mneby-iglite-v11/",workflow)

    def test_owner_temporary_mode_never_skips_independent_timed_recovery(self):
        src=inspect.getsource(self.v.baseline)
        self.assertIn('MNEBY_IGLITE_TEMPORARY_ONLY_APPROVED',src)
        self.assertIn('Reboot-persistent recovery service is not enabled',src)
        run=inspect.getsource(self.v.live)
        self.assertIn('command(["systemd-run"',run)
        self.assertIn('if command(["systemctl", "is-active", "--quiet", UNIT + ".timer"]',run)
        self.assertIn("remaining_watchdog < TRIAL_SECONDS + MIN_ROLLBACK_MARGIN",run)
        self.assertIn("finally:\n        rollback()",run)

    def test_observer_reports_not_phone_attribution(self):
        src=inspect.getsource(self.v.observe_wifi_tcp_headers)
        self.assertIn("iglite_wifi_android_peer_identified=false",src)
        self.assertIn("iglite_wifi_sni_byte_split=NOT_PROVEN_BY_HEADER_CAPTURE",src)
        self.assertIn("iglite_wifi_15min_window=READY",src)
        self.assertIn("outbound_synack_window20",src)
        self.assertIn("iglite_wifi_pcap_persisted=false",src)

if __name__=="__main__":
    unittest.main()
