#!/usr/bin/env python3
"""Offline tests for MNEBYDNS TZ window=4, clamp toggling, observer metrics, and verdict logic."""
from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import meta_v15_receive_window as receiver
import meta_v26_ru_stage as ru
import meta_v30_actions_adapter as adapter
import meta_v31_sni_evidence as evidence
import mneby_tz_experiment_runner as runner
from mnebydns_iglite_sni_observer import Analyzer, capture_command, locate_sni, parse_pcap


def tls_hello(host):
    name = host.encode("ascii")
    entry = b"\0" + struct.pack("!H", len(name)) + name
    ext_body = struct.pack("!H", len(entry)) + entry
    extension = b"\0\0" + struct.pack("!H", len(ext_body)) + ext_body
    body = (
        b"\x03\x03" + b"Z" * 32 + b"\0" + b"\0\x02" + b"\x13\x01"
        + b"\x01\0" + struct.pack("!H", len(extension)) + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def packet(seq, flags, contents=b"", sport=42424):
    tcp = struct.pack("!HHIIHHHH", sport, 443, seq, 0, (5 << 12) | flags, 4096, 0, 0)
    ip = (
        b"\x45\0" + struct.pack("!H", 20 + len(tcp) + len(contents))
        + b"\0\0\0\0\x40\x06\0\0" + b"\xcb\x00\x71\x02" + b"\x59\x7d\x5a\x65"
    )
    return b"\0" * 12 + b"\x08\0" + ip + tcp + contents


def make_pcap(records):
    hdr = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 1600, 1)
    for pkt in records:
        hdr += struct.pack("<IIII", 1, 1, len(pkt), len(pkt)) + pkt
    return io.BytesIO(hdr)


class ClampAndWindowTests(unittest.TestCase):
    def test_nft_rules_supports_window_4_and_clamp_off(self):
        rules_w4 = receiver.nft_rules(ru.RU_EDGE, "8.8.8.8", interface="ens3", window=4, clamp=True)
        self.assertIn("tcp window > 4 counter tcp window set 4", rules_w4)
        self.assertIn("dnat ip to 188.120.254.223:18443", rules_w4)

        rules_off = receiver.nft_rules(ru.RU_EDGE, "8.8.8.8", interface="ens3", window=4, clamp=False)
        self.assertNotIn("tcp window set", rules_off)
        self.assertIn("add chain inet mneby_meta_v15 out", rules_off)
        self.assertIn("dnat ip to 188.120.254.223:18443", rules_off)
        self.assertIn("meta mark set meta mark | 0x40000000", rules_off)

        rules_w16 = receiver.nft_rules(ru.RU_EDGE, "8.8.8.8", interface="ens3", window=16, clamp=True)
        self.assertIn("tcp window > 16 counter tcp window set 16", rules_w16)

        for bad_w in (0, 2, 32, True):
            with self.assertRaises(ValueError):
                receiver.nft_rules(ru.RU_EDGE, "8.8.8.8", window=bad_w)
        with self.assertRaises(ValueError):
            receiver.nft_rules(ru.RU_EDGE, "8.8.8.8", clamp="off")

    def test_window_proxy_forwards_prefix_timeout_to_read_prefix(self):
        with self.assertRaises(ValueError):
            receiver.WindowProxy("188.120.254.223", "8.8.8.8", prefix_timeout=999)

        proxy = receiver.WindowProxy("188.120.254.223", "8.8.8.8", prefix_timeout=25)
        proxy.slots.acquire()
        conn = Mock()
        conn.getsockopt.side_effect = [b"\x00\x02\x01\xbb" + b"\xbc\x78\xfe\xdf" + b"\0" * 8, b"\0" * 16]
        with patch.object(receiver, "read_prefix", side_effect=OSError("stop_after_read")) as rp:
            proxy.handle(conn)
        rp.assert_called_once_with(conn, timeout=25)

    def test_ru_stage_supports_window_16_and_prefix_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "state"
            commands = []
            timer_armed = {"on": False}

            def rich_cmd(argv, **kwargs):
                commands.append(list(argv))
                if argv[:2] == ["ip", "-j"]:
                    return SimpleNamespace(returncode=0, stdout='[{"dev":"tg-relay"}]')
                if argv[:2] == ["ip", "-4"]:
                    return SimpleNamespace(returncode=0, stdout="2: ens3    inet 188.120.254.223/24")
                if argv[:2] == ["sysctl", "-n"]:
                    return SimpleNamespace(returncode=0, stdout="1\n")
                if argv[:2] == ["ss", "-H"]:
                    return SimpleNamespace(returncode=0, stdout="" if f":{ru.TEST_PORT}" in " ".join(argv) else "LISTEN 0 4096 0.0.0.0:443")
                if argv[:2] == ["nft", "-j"]:
                    return SimpleNamespace(returncode=0, stdout=json.dumps({
                        "nftables": [{"rule": {"expr": [
                            {"match": {"op": "==", "left": {"&": [{"meta": {"key": "mark"}}, receiver.BYPASS]}, "right": 0}},
                            {"queue": {"num": 210}},
                        ]}}]
                    }))
                if argv[:2] == ["systemd-run", "--quiet"] and f"{ru.UNIT}" in argv:
                    timer_armed["on"] = True
                    return SimpleNamespace(returncode=0, stdout="")
                return SimpleNamespace(returncode=0, stdout="")

            def fake_active(name):
                if name == "wg-quick@tg-relay.service":
                    return True
                if name == f"{ru.UNIT}.timer":
                    return timer_armed["on"]
                return False

            with patch.object(ru, "ROOT", root), \
                 patch.object(ru, "owner_flag"), \
                 patch.object(ru, "active", side_effect=fake_active), \
                 patch.object(ru, "table_exists", side_effect=[False, True]), \
                 patch.object(ru, "verify_non_meta_fallback"), \
                 patch.object(ru, "firewall_present", return_value=False), \
                 patch.object(ru, "firewall_install"), \
                 patch.object(ru, "ready_worker", return_value=True), \
                 patch.object(ru, "evidence_ready", return_value=True), \
                 patch.object(ru, "verify_tls_path", return_value=1), \
                 patch.object(ru, "cmd", side_effect=rich_cmd):
                ru.start("8.8.8.8", window=16, prefix_timeout=25)

            worker_cmds = [c for c in commands if any("meta_v15_receive_window.py" in str(a) for a in c)]
            self.assertEqual(len(worker_cmds), 1)
            self.assertIn("--window", worker_cmds[0])
            self.assertEqual(worker_cmds[0][worker_cmds[0].index("--window") + 1], "16")
            self.assertIn("--prefix-timeout", worker_cmds[0])
            self.assertEqual(worker_cmds[0][worker_cmds[0].index("--prefix-timeout") + 1], "25")
            self.assertEqual((root / "window").read_text(), "16")
            self.assertEqual((root / "prefix_timeout").read_text(), "25")

    def test_runner_and_termux_script_support_clamped_timeout_and_workflow_inputs(self):
        seen_timeouts = []

        def fake_probe(sni, *, edge_ip=runner.RU_EDGE, timeout=10, url_path="/", **kwargs):
            seen_timeouts.append((sni, timeout))
            return {"ok": True, "http": 200, "time_connect": "0.05", "time_appconnect": "0.10", "comment": ""}

        with tempfile.TemporaryDirectory() as d:
            script_path = Path(d) / "run.sh"
            with patch.object(runner, "probe_curl", side_effect=fake_probe):
                runner.main([
                    "run", "--run-id", "t1", "--operator", "wifi_ru", "--network-type", "wifi",
                    "--cells", "A", "B", "--attempts", "1", "--pause", "0",
                    "--timeout", "10", "--clamped-timeout", "25",
                ])
            self.assertEqual(seen_timeouts, [("gemini.google.com", 10), ("gemini.google.com", 25)])

            runner.main([
                "generate-termux-script", "--run-id", "t1", "--operator", "wifi_ru",
                "--network-type", "wifi", "--timeout", "10", "--clamped-timeout", "25",
                "--out", str(script_path),
            ])
            text = script_path.read_text(encoding="utf-8")
            self.assertIn("UNCLAMPED_TIMEOUT=10", text)
            self.assertIn("CLAMPED_TIMEOUT=25", text)

        wf_path = Path(__file__).resolve().parents[2] / ".github/workflows/meta-v30-manual-two-server-canary.yml"
        wf_text = wf_path.read_text(encoding="utf-8")
        self.assertIn("options: ['8', '4', '16']", wf_text)
        self.assertIn("prefix_timeout:", wf_text)
        self.assertIn("options: ['12', '25', '30']", wf_text)
        self.assertIn("unclamped_seconds:", wf_text)

    def test_ru_stage_set_clamp_off_and_on_with_window_4(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "armed").write_text("armed\n")
            (root / "peer").write_text("all")
            (root / "window").write_text("4")
            (root / "clamp").write_text("on")
            commands = []

            def fake_cmd(argv, **kwargs):
                commands.append((tuple(argv), kwargs.get("input", "")))
                return SimpleNamespace(returncode=0, stdout="")

            with patch.object(ru, "ROOT", root), \
                 patch.object(ru, "owner_flag"), \
                 patch.object(ru, "table_exists", return_value=True), \
                 patch.object(ru, "cmd", side_effect=fake_cmd):
                ru.set_clamp("off")
                self.assertEqual((root / "clamp").read_text(), "off")
                self.assertEqual((root / "window").read_text(), "4")
                applied_off = [inp for argv, inp in commands if argv[:2] == ("nft", "-f")][-1]
                self.assertTrue(applied_off.startswith(f"flush table inet {ru.TABLE}\n"))
                self.assertNotIn("tcp window set", applied_off)

                ru.set_clamp("on")
                self.assertEqual((root / "clamp").read_text(), "on")
                applied_on = [inp for argv, inp in commands if argv[:2] == ("nft", "-f")][-1]
                self.assertIn("tcp window set 4", applied_on)


class ObserverAndEvidenceMetricsTests(unittest.TestCase):
    def test_observer_records_first_segment_le4_and_other_sni_metrics(self):
        hello_ig = tls_hello("i.instagram.com")
        hello_yt = tls_hello("www.youtube.com")
        collector = evidence.CaptureEvidence("8.8.8.8", Path("unused.json"))

        # Flow 1: target host split with 4-byte first segment (Cell D).
        pkts = [packet(100, 2)]
        pkts.append(packet(101, 24, hello_ig[:4]))
        split_at = locate_sni(hello_ig)[1] + 5
        pkts.append(packet(105, 24, hello_ig[4:split_at]))
        pkts.append(packet(101 + split_at, 24, hello_ig[split_at:]))

        # Flow 2: target host unsplit (Cell C).
        pkts.append(packet(200, 2, sport=42425))
        pkts.append(packet(201, 24, hello_ig, sport=42425))

        # Flow 3: control host split with 4-byte first segment (Cell B).
        pkts.append(packet(300, 2, sport=42426))
        pkts.append(packet(301, 24, hello_yt[:4], sport=42426))
        yt_split = locate_sni(hello_yt)[1] + 4
        pkts.append(packet(305, 24, hello_yt[4:yt_split], sport=42426))
        pkts.append(packet(301 + yt_split, 24, hello_yt[yt_split:], sport=42426))

        parse_pcap(make_pcap(pkts), collector.analyzer)
        collector.finished = True
        collector.drops = 0
        report = collector.report()

        tz = report["tz_segment_metrics"]
        self.assertEqual(tz["first_segment_le4"], 1)
        self.assertEqual(tz["first_segment_le8"], 1)
        self.assertEqual(tz["multi_segment_hello"], 1)
        self.assertEqual(tz["other_sni"], 1)
        self.assertEqual(tz["other_sni_split"], 1)
        self.assertEqual(tz["other_first_segment_le4"], 1)
        self.assertEqual(len(report["flow_details"]), 3)
        self.assertEqual(report["flow_details"][0]["first_segment_len"], 4)
        self.assertEqual(report["flow_details"][1]["split"], False)

        # Standard final_verdict rejects mixed unsplit+split, whereas validate_tz_report accepts phased run.
        self.assertEqual(report["verdict"], "UNSPLIT_SNI_OBSERVED")
        self.assertEqual(evidence.validate_tz_report(report, require_split=True), "TZ_PHASED_SNI_SPLIT_OBSERVED")

        # Indeterminate boundaries still fail closed under validate_tz_report.
        bad_report = json.loads(json.dumps(report))
        bad_report["stats"]["sni_boundary_indeterminate"] = 1
        with self.assertRaisesRegex(RuntimeError, "INDETERMINATE"):
            evidence.validate_tz_report(bad_report)

        # Phased validation accepts tiny-window segmentation even when sni_split is 0
        # (for instance when first segment cuts TLS header at 4 bytes before SNI).
        header_split_report = json.loads(json.dumps(report))
        header_split_report["stats"]["sni_split"] = 0
        header_split_report["tz_segment_metrics"]["first_segment_le8"] = 0
        header_split_report["tz_segment_metrics"]["first_segment_le4"] = 1
        header_split_report["tz_segment_metrics"]["multi_segment_hello"] = 1
        self.assertEqual(
            evidence.validate_tz_report(header_split_report, require_split=True),
            "TZ_PHASED_SNI_SPLIT_OBSERVED",
        )

    def test_capture_command_snaplen_1600_and_mtu_split_not_treated_as_window_split(self):
        cmd = capture_command(edge=ru.RU_EDGE, peer="8.8.8.8")
        s_idx = cmd.index("-s")
        self.assertEqual(cmd[s_idx + 1], "1600")

        # Simulate an unclamped post-quantum ClientHello (>1448 bytes):
        # segment 1 fills 1448 payload bytes (1502 Ethernet bytes with 20B IP + 20B TCP + 14B Eth)
        # and keeps SNI intact in segment 1 while wrapping a padding extension into segment 2.
        small = tls_hello("i.instagram.com")
        pad_ext = b"\x00\x15" + struct.pack("!H", 1450) + b"\x00" * 1450
        name = b"i.instagram.com"
        sni_entry = b"\0" + struct.pack("!H", len(name)) + name
        sni_body = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = b"\0\0" + struct.pack("!H", len(sni_body)) + sni_body
        exts = sni_ext + pad_ext
        body = (
            b"\x03\x03" + b"Z" * 32 + b"\0" + b"\0\x02" + b"\x13\x01"
            + b"\x01\0" + struct.pack("!H", len(exts)) + exts
        )
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        big_hello = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
        self.assertGreater(len(big_hello), 1448)
        self.assertGreater(len(small), 50)

        collector = evidence.CaptureEvidence("8.8.8.8", Path("unused.json"))
        pkts = [
            packet(100, 2, sport=42430),
            packet(101, 16, big_hello[:1448], sport=42430),
            packet(101 + 1448, 24, big_hello[1448:], sport=42430),
        ]
        parse_pcap(make_pcap(pkts), collector.analyzer)
        collector.finished = True
        collector.drops = 0
        report = collector.report()

        self.assertEqual(report["stats"]["target_clienthello"], 1)
        self.assertEqual(report["stats"]["sni_split"], 0)
        self.assertEqual(report["stats"]["sni_unsplit"], 1)
        self.assertEqual(report["tz_segment_metrics"]["first_segment_le4"], 0)
        self.assertEqual(report["tz_segment_metrics"]["first_segment_le8"], 0)
        self.assertEqual(report["tz_segment_metrics"]["multi_segment_hello"], 1)
        with self.assertRaisesRegex(RuntimeError, "NO_SPLIT_SNI_OBSERVED"):
            evidence.validate_tz_report(report, require_split=True)
        self.assertEqual(
            evidence.validate_tz_report(report, require_split=False),
            "TZ_PHASED_CAPTURE_VALID",
        )


class PhasedAdapterTests(unittest.TestCase):
    def test_adapter_phased_mode_toggles_clamp_and_validates_mixed_report(self):
        calls = []

        class FakeRemote:
            def preflight(self, role):
                calls.append(("preflight", role))

            def stage_files(self, role):
                calls.append(("stage", role))

            def run(self, role, action, peer=None):
                calls.append(("run", role, action, peer))
                if action == "evidence":
                    return json.dumps({
                        "schema": 1,
                        "capture_point": evidence.POINT,
                        "worker_pid": 123,
                        "updated_at": 9999999999.0,
                        "final": True,
                        "capture_ok": True,
                        "kernel_drops": 0,
                        "stats": {
                            "syn": 2,
                            "target_clienthello": 2,
                            "sni_split": 1,
                            "sni_unsplit": 1,
                            "sni_boundary_indeterminate": 0,
                            "evictions": 0,
                            "payload_without_syn": 0,
                        },
                    })
                return ""

            def active_window(self, seconds, *, clamp_mode="on", unclamped_seconds=540):
                calls.append(("window", seconds, clamp_mode, unclamped_seconds))

            def collect_evidence(self, *, final=False, require_success=False):
                calls.append(("collect", final, require_success))
                return json.loads(self.run("ru", "evidence"))

            def reset(self, role):
                calls.append(("reset", role))

        with patch.object(adapter, "Remote", return_value=FakeRemote()) as remote_cls, \
             patch.dict(os.environ, {
                 "GITHUB_EVENT_NAME": "workflow_dispatch",
                 "MNEBY_META_V30_APPROVED": adapter.APPROVAL,
             }), \
             patch.object(adapter.signal, "signal"):
            adapter.main([
                "--mode", "activate",
                "--phone-ip", "all",
                "--minutes", "15",
                "--clamp-mode", "phased",
                "--unclamped-seconds", "240",
                "--window", "4",
            ])
        remote_cls.assert_called_once_with(window=4)
        self.assertIn(("window", 900, "phased", 240), calls)
        self.assertIn(("collect", True, False), calls)

    def test_adapter_default_unclamped_seconds_is_540(self):
        calls = []

        class FakeRemote:
            def preflight(self, role):
                pass

            def stage_files(self, role):
                pass

            def run(self, role, action, peer=None):
                return json.dumps({
                    "schema": 1,
                    "capture_point": evidence.POINT,
                    "worker_pid": 123,
                    "updated_at": 9999999999.0,
                    "final": True,
                    "capture_ok": True,
                    "kernel_drops": 0,
                    "stats": {
                        "syn": 1, "target_clienthello": 1, "sni_split": 1,
                        "sni_unsplit": 0, "sni_boundary_indeterminate": 0,
                        "evictions": 0, "payload_without_syn": 0,
                    },
                }) if action == "evidence" else ""

            def active_window(self, seconds, *, clamp_mode="on", unclamped_seconds=540):
                calls.append((seconds, clamp_mode, unclamped_seconds))

            def collect_evidence(self, *, final=False, require_success=False):
                return json.loads(self.run("ru", "evidence"))

            def reset(self, role):
                pass

        with patch.object(adapter, "Remote", return_value=FakeRemote()), \
             patch.dict(os.environ, {
                 "GITHUB_EVENT_NAME": "workflow_dispatch",
                 "MNEBY_META_V30_APPROVED": adapter.APPROVAL,
             }), \
             patch.object(adapter.signal, "signal"):
            adapter.main([
                "--mode", "activate", "--phone-ip", "all",
                "--minutes", "30", "--clamp-mode", "phased",
            ])
        self.assertEqual(calls, [(1800, "phased", 540)])


class TZVerdictsAndRunnerTests(unittest.TestCase):
    def test_section_7_2_verdict_table(self):
        self.assertEqual(runner.verdict_network(2, 18), "РАБОТАЕТ")
        self.assertEqual(runner.verdict_network(0, 20), "РАБОТАЕТ")
        self.assertEqual(runner.verdict_network(1, 2), "НЕ РАБОТАЕТ: ТСПУ собирает поток")
        self.assertTrue(runner.verdict_network(2, 10).startswith("НЕСТАБИЛЬНО"))
        self.assertTrue(runner.verdict_network(18, 19).startswith("ФИЛЬТРА НА УЧАСТКЕ НЕТ"))
        self.assertTrue(runner.verdict_network(5, 20).startswith("ФИЛЬТР ПЛАВАЮЩИЙ"))
        self.assertTrue(runner.verdict_network(19, 5).startswith("ДЕГРАДАЦИЯ ПРИ CLAMP"))

    def test_section_7_2_repeatability(self):
        self.assertEqual(
            runner.network_repeatability_verdict(["РАБОТАЕТ"] * 5 + ["НЕ РАБОТАЕТ: ТСПУ собирает поток"]),
            "УСТОЙЧИВО РАБОТАЕТ",
        )
        self.assertTrue(
            runner.network_repeatability_verdict(["РАБОТАЕТ"] * 4 + ["НЕ РАБОТАЕТ: ТСПУ собирает поток"] * 2).startswith("НЕУСТОЙЧИВО")
        )

    def test_section_7_3_overall_verdict(self):
        self.assertTrue(runner.overall_verdict([
            {"network_type": "mobile", "verdict": "РАБОТАЕТ"},
            {"network_type": "wifi", "verdict": "РАБОТАЕТ"},
            {"network_type": "mobile", "verdict": "НЕ РАБОТАЕТ: ТСПУ собирает поток"},
        ]).startswith("СПОСОБ РАБОЧИЙ"))

        # Two Wi-Fi networks without any mobile network cannot pass overall Section 7.3 requirement.
        self.assertTrue(runner.overall_verdict([
            {"network_type": "wifi", "verdict": "РАБОТАЕТ"},
            {"network_type": "wifi", "verdict": "РАБОТАЕТ"},
            {"network_type": "mobile", "verdict": "НЕ РАБОТАЕТ: ТСПУ собирает поток"},
        ]).startswith("НЕОБЯЗАТЕЛЬНЫЙ ПРОФИЛЬ"))

        self.assertTrue(runner.overall_verdict([
            {"network_type": "mobile", "verdict": "НЕ РАБОТАЕТ: ТСПУ собирает поток"},
            {"network_type": "mobile", "verdict": "НЕ РАБОТАЕТ: ТСПУ собирает поток"},
            {"network_type": "wifi", "verdict": "НЕ РАБОТАЕТ: ТСПУ собирает поток"},
        ]).startswith("ЧИСТО СЕРВЕРНОГО РЕШЕНИЯ НЕТ"))

    def test_validity_v1_v2_v3_and_csv_evidence_matching(self):
        rows = []
        for idx in range(1, 21):
            rows.append({
                "run_id": "r1",
                "дата_время": f"2026-11-13T20:00:{idx:02d}Z",
                "оператор": "MTS",
                "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4",
                "ячейка": "A",
                "попытка": str(idx),
                "SNI": "www.youtube.com",
                "clamp": "выкл",
                "результат": "УСПЕХ",
                "http": "200",
                "time_connect": "0.1",
                "time_appconnect": "0.2",
                "длина_первого_сегмента": "",
                "комментарий": "",
            })
        for idx in range(1, 21):
            rows.append({
                "run_id": "r1",
                "дата_время": f"2026-11-13T20:01:{idx:02d}Z",
                "оператор": "MTS",
                "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4",
                "ячейка": "C",
                "попытка": str(idx),
                "SNI": "i.instagram.com",
                "clamp": "выкл",
                "результат": "СБОЙ",
                "http": "000",
                "time_connect": "0",
                "time_appconnect": "0",
                "длина_первого_сегмента": "",
                "комментарий": "",
            })
        for idx in range(1, 21):
            rows.append({
                "run_id": "r1",
                "дата_время": f"2026-11-13T20:03:{idx:02d}Z",
                "оператор": "MTS",
                "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4",
                "ячейка": "B",
                "попытка": str(idx),
                "SNI": "www.youtube.com",
                "clamp": "вкл",
                "результат": "УСПЕХ",
                "http": "200",
                "time_connect": "0.1",
                "time_appconnect": "0.2",
                "длина_первого_сегмента": "",
                "комментарий": "",
            })
        for idx in range(1, 21):
            rows.append({
                "run_id": "r1",
                "дата_время": f"2026-11-13T20:04:{idx:02d}Z",
                "оператор": "MTS",
                "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4",
                "ячейка": "D",
                "попытка": str(idx),
                "SNI": "i.instagram.com",
                "clamp": "вкл",
                "результат": "УСПЕХ",
                "http": "200",
                "time_connect": "0.1",
                "time_appconnect": "0.2",
                "длина_первого_сегмента": "",
                "комментарий": "",
            })

        base_a = 1794600000  # just synthetic epochs aligned via ISO timestamps below:
        # Build flow_details with exact ISO timestamps from rows above.
        import datetime as dt
        flows = []
        for r in rows:
            if r["ячейка"] in ("A", "B", "D"):
                ep = int(dt.datetime.fromisoformat(r["дата_время"].replace("Z", "+00:00")).timestamp())
                flows.append({
                    "utc_epoch": ep,
                    "host": r["SNI"],
                    "target": r["ячейка"] == "D",
                    "split": r["ячейка"] in ("B", "D"),
                    "first_segment_len": 4 if r["ячейка"] in ("B", "D") else 517,
                    "segments": 3 if r["ячейка"] in ("B", "D") else 1,
                })

        summary = runner.evaluate_rows(
            rows,
            speed_a_bps=1_000_000.0,
            speed_b_bps=850_000.0,
            evidence={"flow_details": flows},
        )
        self.assertEqual(summary["validity"]["V1"]["status"], "PASS")
        self.assertEqual(summary["validity"]["V2"]["status"], "PASS")
        self.assertEqual(summary["validity"]["V3"]["status"], "PASS")
        self.assertTrue(summary["validity"]["valid_for_verdict"])
        self.assertEqual(summary["network_verdict"], "РАБОТАЕТ")

        # Ensure failed Cell C rows did NOT consume Cell D flows!
        attached = runner.attach_evidence_to_rows(rows, {"flow_details": flows})
        cell_c_lens = [r["длина_первого_сегмента"] for r in attached if r["ячейка"] == "C"]
        cell_d_lens = [r["длина_первого_сегмента"] for r in attached if r["ячейка"] == "D"]
        self.assertTrue(all(v == "" for v in cell_c_lens))
        self.assertEqual(cell_d_lens, ["4"] * 20)

    def test_stage2_criteria(self):
        ok = runner.evaluate_stage2(
            instagram_ok=20, instagram_total=20,
            cdn_speed_bps=750_000, de_baseline_bps=1_000_000,
            zero_bytes_200_count=1, total_200_count=100,
            wg_max_packet_bytes=1360,
        )
        self.assertTrue(ok["pass"])
        bad = runner.evaluate_stage2(
            instagram_ok=20, instagram_total=20,
            cdn_speed_bps=650_000, de_baseline_bps=1_000_000,
            zero_bytes_200_count=2, total_200_count=100,
            wg_max_packet_bytes=1400,
        )
        self.assertFalse(bad["pass"])
        self.assertFalse(bad["checks"]["cdn_speed_ge_70pct"])
        self.assertFalse(bad["checks"]["sni_log_zero_bytes_le_1pct"])
        self.assertFalse(bad["checks"]["wg0_mtu_le_1360"])

    def test_runner_executes_punish_check_on_cell_c_failure_and_writes_csv(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = Path(d) / "out.csv"

            def fake_probe(sni, *, edge_ip=runner.RU_EDGE, timeout=10, url_path="/"):
                if sni == "i.instagram.com":
                    return {"ok": False, "http": 0, "time_connect": "0", "time_appconnect": "0", "comment": "timeout"}
                return {"ok": True, "http": 200, "time_connect": "0.05", "time_appconnect": "0.10", "comment": ""}

            with patch.object(runner, "probe_curl", side_effect=fake_probe):
                runner.main([
                    "run",
                    "--run-id", "test1",
                    "--operator", "Beeline",
                    "--network-type", "mobile",
                    "--client-ip", "1.2.3.4",
                    "--cells", "C",
                    "--attempts", "1",
                    "--pause", "0",
                    "--out-csv", str(csv_path),
                ])
            with csv_path.open("r", encoding="utf-8") as fh:
                parsed = list(csv.DictReader(fh))
            self.assertEqual(tuple(parsed[0].keys()), runner.CSV_HEADER)
            self.assertIn("ip_punish_check=PASS", parsed[0]["комментарий"])

    def test_termux_script_syntax_valid(self):
        with tempfile.TemporaryDirectory() as d:
            script_path = Path(d) / "termux.sh"
            runner.main(["generate-termux-script", "--run-id", "m1", "--operator", "Megafon", "--out", str(script_path)])
            text = script_path.read_text(encoding="utf-8")
            self.assertIn("CONTROL_SNI=gemini.google.com", text)
            self.assertIn("run_one A", text)
            self.assertIn("run_one C", text)
            self.assertIn("run_one B", text)
            self.assertIn("run_one D", text)
            self.assertIn("run_one E", text)
            proc = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_default_control_sni_and_phase_interleaving_schedule(self):
        self.assertEqual(runner.DEFAULT_CONTROL_SNI, "gemini.google.com")
        sched = runner.build_schedule(attempts=2)
        self.assertEqual(
            [(item.cell, item.attempt, item.sni, item.clamp) for item in sched],
            [
                ("A", 1, "gemini.google.com", "выкл"),
                ("C", 1, "i.instagram.com", "выкл"),
                ("A", 2, "gemini.google.com", "выкл"),
                ("C", 2, "i.instagram.com", "выкл"),
                ("B", 1, "gemini.google.com", "вкл"),
                ("D", 1, "i.instagram.com", "вкл"),
                ("E", 1, "graph.instagram.com", "вкл"),
                ("B", 2, "gemini.google.com", "вкл"),
                ("D", 2, "i.instagram.com", "вкл"),
                ("E", 2, "graph.instagram.com", "вкл"),
            ],
        )

    def test_attach_evidence_ignores_ip_punish_check_flows_and_fallback_v2_uses_b_count(self):
        rows = []
        flows = []
        # Interleaved Phase 1: 20 x A (517B) + 20 x C (failed + ip_punish_check=PASS 517B).
        for idx in range(1, 21):
            rows.append({
                "run_id": "r2", "дата_время": "", "оператор": "T2", "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4", "ячейка": "A", "попытка": str(idx),
                "SNI": "gemini.google.com", "clamp": "выкл", "результат": "УСПЕХ",
                "http": "200", "time_connect": "0.1", "time_appconnect": "0.2",
                "длина_первого_сегмента": "", "комментарий": "",
            })
            flows.append({
                "utc_epoch": 0, "host": "gemini.google.com", "target": False,
                "split": False, "first_segment_len": 517, "segments": 1,
            })
            rows.append({
                "run_id": "r2", "дата_время": "", "оператор": "T2", "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4", "ячейка": "C", "попытка": str(idx),
                "SNI": "i.instagram.com", "clamp": "выкл", "результат": "СБОЙ",
                "http": "000", "time_connect": "0", "time_appconnect": "0",
                "длина_первого_сегмента": "", "комментарий": "timeout; ip_punish_check=PASS",
            })
            flows.append({
                "utc_epoch": 0, "host": "gemini.google.com", "target": False,
                "split": False, "first_segment_len": 517, "segments": 1,
            })
        # Phase 2: 20 x B (clamped 4B) + 20 x D (clamped 4B).
        for idx in range(1, 21):
            rows.append({
                "run_id": "r2", "дата_время": "", "оператор": "T2", "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4", "ячейка": "B", "попытка": str(idx),
                "SNI": "gemini.google.com", "clamp": "вкл", "результат": "УСПЕХ",
                "http": "200", "time_connect": "0.1", "time_appconnect": "0.2",
                "длина_первого_сегмента": "", "комментарий": "",
            })
            flows.append({
                "utc_epoch": 0, "host": "gemini.google.com", "target": False,
                "split": True, "first_segment_len": 4, "segments": 3,
            })
            rows.append({
                "run_id": "r2", "дата_время": "", "оператор": "T2", "тип_сети": "mobile",
                "внешний_IP": "1.2.3.4", "ячейка": "D", "попытка": str(idx),
                "SNI": "i.instagram.com", "clamp": "вкл", "результат": "УСПЕХ",
                "http": "200", "time_connect": "0.1", "time_appconnect": "0.2",
                "длина_первого_сегмента": "", "комментарий": "",
            })
            flows.append({
                "utc_epoch": 0, "host": "i.instagram.com", "target": True,
                "split": True, "first_segment_len": 4, "segments": 3,
            })

        matched = runner.attach_evidence_to_rows(rows, {"flow_details": flows})
        a_lens = [r["длина_первого_сегмента"] for r in matched if r["ячейка"] == "A"]
        b_lens = [r["длина_первого_сегмента"] for r in matched if r["ячейка"] == "B"]
        c_lens = [r["длина_первого_сегмента"] for r in matched if r["ячейка"] == "C"]
        d_lens = [r["длина_первого_сегмента"] for r in matched if r["ячейка"] == "D"]
        self.assertEqual(a_lens, ["517"] * 20)
        self.assertEqual(b_lens, ["4"] * 20)
        self.assertEqual(c_lens, [""] * 20)
        self.assertEqual(d_lens, ["4"] * 20)

        # Even if flow_details is empty, aggregate V2 uses len(B)=20 instead of other_sni=60.
        agg_validity = runner.evaluate_validity(
            rows,
            speed_a_bps=1_000_000.0,
            speed_b_bps=900_000.0,
            evidence={"tz_segment_metrics": {"other_sni": 60, "other_first_segment_le4": 20}},
        )
        self.assertEqual(agg_validity["V2"]["status"], "PASS")
        self.assertEqual(agg_validity["V2"]["le4"], 20)
        self.assertEqual(agg_validity["V2"]["total"], 20)

    def test_curves_option_forwarded_to_curl_and_termux_script(self):
        cmds = []

        def fake_subproc(cmd, **kwargs):
            cmds.append(list(cmd))
            return SimpleNamespace(returncode=0, stdout="200 0.03 0.12", stderr="")

        with patch.object(runner.subprocess, "run", side_effect=fake_subproc):
            res = runner.probe_curl("i.instagram.com", curves="X25519")
        self.assertTrue(res["ok"])
        idx = cmds[0].index("--curves")
        self.assertEqual(cmds[0][idx + 1], "X25519")

        with self.assertRaises(ValueError):
            runner.probe_curl("i.instagram.com", curves="X25519; rm -rf /")

        with tempfile.TemporaryDirectory() as d:
            script_path = Path(d) / "curves.sh"
            runner.main([
                "generate-termux-script", "--run-id", "c1", "--operator", "wifi_ru",
                "--network-type", "wifi", "--curves", "X25519", "--out", str(script_path),
            ])
            text = script_path.read_text(encoding="utf-8")
            self.assertIn("CURVES=X25519", text)
            self.assertIn("--curves", text)
            proc = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_termux_script_fixes_curl_timeout_concatenation_and_partial_200_punish(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            curl_shim = bin_dir / "curl"
            curl_shim.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "url = sys.argv[-1]\n"
                "args = ' '.join(sys.argv[1:])\n"
                "if 'api.ipify.org' in url:\n"
                "    sys.stdout.write('185.137.178.123')\n"
                "    sys.exit(0)\n"
                "if 'i.instagram.com' in url:\n"
                "    sys.stdout.write('000 0.000000 0.000000')\n"
                "    sys.exit(28)\n"
                "if 'gemini.google.com' in url:\n"
                "    if '%{time_appconnect}' in args:\n"
                "        sys.stdout.write('200 0.030000 0.190000')\n"
                "        sys.exit(0)\n"
                "    sys.stdout.write('200')\n"
                "    sys.exit(28)\n"
                "sys.exit(1)\n",
                encoding="utf-8",
            )
            curl_shim.chmod(0o755)
            script_path = tmp / "run.sh"
            csv_path = tmp / "out.csv"
            runner.main([
                "generate-termux-script", "--run-id", "p3", "--operator", "wifi_ru",
                "--network-type", "wifi", "--attempts", "1", "--pause", "0",
                "--out", str(script_path),
            ])
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
            proc = subprocess.run(
                ["bash", str(script_path), "unclamped", str(csv_path)],
                env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = runner.read_csv(csv_path)
            self.assertEqual([r["ячейка"] for r in rows], ["A", "C"])
            row_c = rows[1]
            self.assertEqual(row_c["time_appconnect"], "0.000000")
            self.assertIn("ip_punish_check=PASS", row_c["комментарий"])
            self.assertNotIn("200000", row_c["комментарий"])
            self.assertFalse(runner.evaluate_rows(rows)["ip_punishment_observed"])

    def test_python_runner_and_termux_enforce_phase_deadlines_and_partial_punish(self):
        called = []

        def fake_probe(sni, *, edge_ip=runner.RU_EDGE, timeout=10, url_path="/"):
            called.append(sni)
            if sni == "i.instagram.com":
                return {"ok": False, "http": 0, "time_connect": "0", "time_appconnect": "0", "comment": "timeout"}
            if len(called) == 2:
                return {"ok": False, "http": 200, "time_connect": "0.03", "time_appconnect": "0.18", "comment": "curl_rc=28"}
            return {"ok": True, "http": 200, "time_connect": "0.03", "time_appconnect": "0.18", "comment": ""}

        with tempfile.TemporaryDirectory() as d:
            csv_partial = Path(d) / "partial.csv"
            with patch.object(runner, "probe_curl", side_effect=fake_probe):
                runner.main([
                    "run", "--run-id", "r_p", "--operator", "wifi_ru", "--network-type", "wifi",
                    "--cells", "C", "--attempts", "1", "--pause", "0", "--out-csv", str(csv_partial),
                ])
            rows_p = runner.read_csv(csv_partial)
            self.assertIn("ip_punish_check=PASS(partial)", rows_p[0]["комментарий"])
            self.assertFalse(runner.evaluate_rows(rows_p)["ip_punishment_observed"])

            # Expired phase1 deadline prevents unclamped probes while future phase2 still executes.
            called.clear()
            csv_guarded = Path(d) / "guarded.csv"
            with patch.object(runner, "probe_curl", side_effect=fake_probe):
                runner.main([
                    "run", "--run-id", "r_g", "--operator", "wifi_ru", "--network-type", "wifi",
                    "--cells", "A", "C", "B", "--attempts", "1", "--pause", "0",
                    "--phase1-deadline-utc", "1000", "--phase2-deadline-utc", "9999999999",
                    "--out-csv", str(csv_guarded),
                ])
            rows_g = runner.read_csv(csv_guarded)
            self.assertEqual([r["ячейка"] for r in rows_g], ["B"])

            # Bash script stops unclamped loop cleanly if PHASE1_DEADLINE_UTC has passed.
            bin_dir = Path(d) / "bin2"
            bin_dir.mkdir()
            log_file = Path(d) / "calls.log"
            shim = bin_dir / "curl"
            shim.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "url = sys.argv[-1]\n"
                "if 'api.ipify.org' in url:\n"
                "    sys.stdout.write('185.137.178.123')\n"
                "    sys.exit(0)\n"
                f"open({str(log_file)!r}, 'a').write(url + '\\n')\n"
                "sys.stdout.write('200 0.03 0.18')\n",
                encoding="utf-8",
            )
            shim.chmod(0o755)
            script_path = Path(d) / "guarded.sh"
            csv_sh = Path(d) / "sh.csv"
            runner.main([
                "generate-termux-script", "--run-id", "g1", "--operator", "wifi_ru",
                "--network-type", "wifi", "--attempts", "2", "--pause", "0",
                "--phase1-deadline-utc", "1000", "--phase2-deadline-utc", "9999999999",
                "--phase-margin", "15", "--out", str(script_path),
            ])
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
            proc = subprocess.run(
                ["bash", str(script_path), "unclamped", str(csv_sh)],
                env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(log_file.exists())
            self.assertEqual(runner.read_csv(csv_sh), [])


class TestPost186Compatibility(unittest.TestCase):
    def test_source_view_render_handles_ru188_baseline_templates(self):
        import meta_v25_source_view as source_view

        corefile = (
            "tls://.:853 {\n"
            "    tls /etc/coredns/fullchain.pem /etc/coredns/privkey.pem\n"
            "    cache 30 {\n"
            "        success 4096\n"
            "    }\n"
            "    template IN A gemini.google.com {\n"
            "        match ^gemini[.]google[.]com[.]$ \n"
            '        answer "{{ .Name }} 20 IN A 188.120.254.223"\n'
            "        fallthrough\n"
            "    }\n"
            "    template IN A www.youtube.com {\n"
            "        match ^www[.]youtube[.]com[.]$ \n"
            '        answer "{{ .Name }} 60 IN A 188.120.254.223"\n'
            "        fallthrough\n"
            "    }\n"
            "    forward . 127.0.0.1:5353\n"
            "}\n"
        )
        plan = source_view.render(
            corefile=corefile,
            phone_ip="185.137.178.123",
            compiled_plugins="view\ntls\ntemplate\nforward\nmetadata\n",
        )
        plan.verify_rollback()
        self.assertIn("view " + source_view.VIEW_NAME, plan.candidate)
        self.assertTrue(plan.candidate.endswith(corefile))

    def test_wire_check_allows_ru_edge_only_when_explicitly_enabled(self):
        import socket
        import mnebydns_iglite_dns_wire_checks as wire

        tid = 0x4242
        question = wire.make_question(wire.QTYPES["A"], tid, "www.youtube.com")
        header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)

        def a_packet(ip: str) -> bytes:
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 20, 4) + socket.inet_aton(ip)
            return header + question[12:] + rr

        ru_pkt = a_packet(wire.RU_EDGE)
        de_pkt = a_packet(wire.EDGE)

        with self.assertRaisesRegex(ValueError, "DE edge"):
            wire.check_answer(ru_pkt, tid, wire.QTYPES["A"], "www.youtube.com")

        self.assertEqual(
            wire.check_answer(
                ru_pkt,
                tid,
                wire.QTYPES["A"],
                "www.youtube.com",
                allowed_edges=wire.ALLOWED_EDGES,
            ),
            "A_EXACT_EDGE",
        )
        self.assertEqual(
            wire.check_answer(
                de_pkt,
                tid,
                wire.QTYPES["A"],
                "www.youtube.com",
                allowed_edges=wire.ALLOWED_EDGES,
            ),
            "A_EXACT_DE",
        )


if __name__ == "__main__":
    unittest.main()
