import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import meta_geneva_dupack as gd
import meta_v26_ru_stage as ru
import meta_v30_actions_adapter as adapter
import meta_v31_sni_evidence as ev
import mneby_tz_experiment_runner as runner
import mnebydns_iglite_sni_observer as obs


def _ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(int.from_bytes(header[i : i + 2], "big") for i in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_tcp_ipv4_packet(
    src_ip: str = "188.120.254.223",
    dst_ip: str = "198.51.100.10",
    sport: int = 443,
    dport: int = 54321,
    seq: int = 1000,
    ack: int = 2001,
    flags: int = 0x12,
    window: int = 64240,
    options: bytes = b"\x02\x04\x05\xb4\x01\x01\x04\x02",
    payload: bytes = b"",
    bad_tcp_sum: bool = False,
    bad_ip_sum: bool = False,
) -> bytes:
    assert len(options) % 4 == 0
    doff = 5 + len(options) // 4
    tcp_wo_sum = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        doff << 4,
        flags,
        window,
        0,
        0,
    ) + options + payload
    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)
    csum = gd.tcp_checksum(src_b, dst_b, tcp_wo_sum)
    if bad_tcp_sum:
        csum ^= 0xFFFF
    tcp_seg = tcp_wo_sum[:16] + struct.pack("!H", csum) + tcp_wo_sum[18:]
    total_len = 20 + len(tcp_seg)
    ip_wo_sum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        0,
        src_b,
        dst_b,
    )
    ip_sum = _ip_checksum(ip_wo_sum)
    if bad_ip_sum:
        ip_sum ^= 0xFFFF
    ip_hdr = ip_wo_sum[:10] + struct.pack("!H", ip_sum) + ip_wo_sum[12:]
    return ip_hdr + tcp_seg


def wrap_eth(ip_packet: bytes) -> bytes:
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip_packet


class GenevaDupAckPacketTests(unittest.TestCase):
    def test_verify_ipv4_tcp_checksum_valid_and_corrupted(self):
        good = make_tcp_ipv4_packet(payload=b"hello")  # odd payload length
        ok, wire, expected = gd.verify_ipv4_tcp_checksum(good)
        self.assertTrue(ok)
        self.assertEqual(wire, expected)

        bad = make_tcp_ipv4_packet(payload=b"hello", bad_tcp_sum=True)
        ok_bad, wire_bad, expected_bad = gd.verify_ipv4_tcp_checksum(bad)
        self.assertFalse(ok_bad)
        self.assertNotEqual(wire_bad, expected_bad)

    def test_build_geneva_dupack_ack_exact_has_valid_ip_and_corrupt_tcp_checksum(self):
        synack = make_tcp_ipv4_packet(seq=0xFFFFFFFE, ack=5001, flags=0x12, window=64240)
        dup = gd.build_geneva_dupack(synack, variant="ack-exact")
        self.assertEqual(len(dup), 40)
        self.assertEqual(_ip_checksum(dup[:20]), 0)
        ok, wire, expected = gd.verify_ipv4_tcp_checksum(dup)
        self.assertFalse(ok)
        self.assertEqual(wire, expected ^ 0xFFFF)

        sport, dport, seq, ack, off_res, flags, win = struct.unpack_from("!HHIIBBH", dup, 20)
        self.assertEqual((sport, dport), (443, 54321))
        self.assertEqual(seq, 0xFFFFFFFF)  # S0 + 1 wrap-safe
        self.assertEqual(ack, 5001)
        self.assertEqual(flags, 0x10)
        self.assertEqual(off_res >> 4, 5)
        self.assertEqual(win, 64240)

    def test_build_geneva_dupack_ack_desync_shifts_seq_and_ack(self):
        synack = make_tcp_ipv4_packet(seq=1000, ack=2001, flags=0x12)
        dup = gd.build_geneva_dupack(synack, variant="ack-desync")
        self.assertEqual(_ip_checksum(dup[:20]), 0)
        ok, _, _ = gd.verify_ipv4_tcp_checksum(dup)
        self.assertFalse(ok)
        _, _, seq, ack, _, flags, _ = struct.unpack_from("!HHIIBBH", dup, 20)
        self.assertEqual(flags, 0x10)
        self.assertEqual(seq, 2001)
        self.assertEqual(ack, 3461)

    def test_build_geneva_dupack_rejects_non_synack_and_bad_inputs(self):
        for flags in (0x02, 0x10, 0x14, 0x18):
            with self.assertRaises(ValueError):
                gd.build_geneva_dupack(make_tcp_ipv4_packet(flags=flags))
        with self.assertRaises(ValueError):
            gd.build_geneva_dupack(b"\x45" * 10)
        with self.assertRaises(ValueError):
            gd.build_geneva_dupack(make_tcp_ipv4_packet(flags=0x12), variant="unknown")


class GenevaNetlinkCodecTests(unittest.TestCase):
    def test_parse_nfq_packet_and_build_verdict(self):
        synack = make_tcp_ipv4_packet(flags=0x12)
        hdr = struct.pack("!IHB", 42, 0x0800, 4)  # NFQA_PACKET_HDR
        attrs = gd.encode_nlattr(gd.NFQA_PACKET_HDR, hdr) + gd.encode_nlattr(gd.NFQA_PAYLOAD, synack)
        nfgen = struct.pack("!BBH", socket.AF_INET, 0, 211)
        nl_type = (gd.NFNL_SUBSYS_QUEUE << 8) | gd.NFQNL_MSG_PACKET
        total_len = 16 + len(nfgen) + len(attrs)
        msg = struct.pack("<IHHII", total_len, nl_type, 0, 1, 0) + nfgen + attrs

        parsed = gd.parse_nfq_packet(msg)
        self.assertIsNotNone(parsed)
        pkt_id, payload = parsed
        self.assertEqual(pkt_id, 42)
        self.assertEqual(payload, synack)

        verdict = gd.build_verdict_msg(queue_num=211, packet_id=42, verdict=gd.NF_ACCEPT, seq=7)
        v_len, v_type, v_flags, v_seq, _ = struct.unpack_from("<IHHII", verdict, 0)
        self.assertEqual(v_len, len(verdict))
        self.assertEqual(v_type, (gd.NFNL_SUBSYS_QUEUE << 8) | gd.NFQNL_MSG_VERDICT)
        self.assertEqual(v_flags, gd.NLM_F_REQUEST)
        self.assertEqual(v_seq, 7)
        fam, ver, res_id = struct.unpack_from("!BBH", verdict, 16)
        self.assertEqual((fam, ver, res_id), (socket.AF_INET, 0, 211))
        nla_len, nla_type = struct.unpack_from("<HH", verdict, 20)
        self.assertEqual((nla_len, nla_type), (12, gd.NFQA_VERDICT_HDR))
        v_code, v_pid = struct.unpack_from("!II", verdict, 24)
        self.assertEqual((v_code, v_pid), (gd.NF_ACCEPT, 42))


class GenevaEgressVerifierAndNftTests(unittest.TestCase):
    def test_egress_verifier_counts_synack_and_badsum_dupack(self):
        verifier = gd.GenevaEgressVerifier(edge="188.120.254.223")
        synack = make_tcp_ipv4_packet(flags=0x12)
        dup_bad = gd.build_geneva_dupack(synack, variant="ack-exact")
        ack_good = make_tcp_ipv4_packet(flags=0x10, bad_tcp_sum=False)
        bad_ip = make_tcp_ipv4_packet(flags=0x10, bad_tcp_sum=True, bad_ip_sum=True)

        verifier.ethernet(wrap_eth(synack))
        verifier.ethernet(wrap_eth(dup_bad))
        verifier.ethernet(wrap_eth(ack_good))
        verifier.ethernet(wrap_eth(bad_ip))

        self.assertEqual(verifier.egress_synack, 1)
        self.assertEqual(verifier.egress_dupack_badsum, 1)
        self.assertEqual(verifier.egress_dupack_valid_sum, 1)

    def test_nft_geneva_rules_isolate_notrack_queue_and_bypass(self):
        rules = gd.nft_geneva_rules(
            "188.120.254.223",
            "198.51.100.10",
            port=18443,
            interface="ens3",
            table="mneby_meta_v26_ru",
            queue_num=211,
        )
        self.assertIn("priority -401", rules)
        self.assertIn("notrack", rules)
        self.assertIn("tcp flags & (syn | ack) == (syn | ack)", rules)
        self.assertIn("queue num 211 bypass", rules)
        self.assertIn("meta mark set meta mark | 0x40000000", rules)
        self.assertLess(rules.index("queue num 211 bypass"), rules.index("meta mark set meta mark | 0x40000000"))

        shared_rules = gd.nft_geneva_rules(
            "188.120.254.223",
            "all",
            port=18443,
            interface="ens3",
            table="mneby_meta_v26_ru",
            queue_num=211,
        )
        self.assertIn("ct status dnat", shared_rules)
        with self.assertRaises(ValueError):
            gd.nft_geneva_rules("192.0.2.1", "all", interface="eth0")


class GenevaEvidenceAndWiringTests(unittest.TestCase):
    def _base_report(self, *, syn=1, target_ch=1, sni_unsplit=1, sni_split=0, synack=1, badsum=2):
        return {
            "schema": 1,
            "capture_point": ev.POINT,
            "worker_pid": 1234,
            "updated_at": 1000.0,
            "capture_ok": True,
            "final": True,
            "kernel_drops": 0,
            "stats": {
                "syn": syn,
                "target_clienthello": target_ch,
                "sni_split": sni_split,
                "sni_unsplit": sni_unsplit,
                "sni_boundary_indeterminate": 0,
                "evictions": 0,
                "payload_without_syn": 0,
            },
            "geneva_metrics": {
                "egress_synack": synack,
                "egress_dupack_badsum": badsum,
            },
        }

    def test_validate_geneva_report_verdicts_and_errors(self):
        ok_report = self._base_report(syn=1, target_ch=1, sni_unsplit=1, sni_split=0, synack=1, badsum=2)
        self.assertEqual(ev.validate_geneva_report(ok_report, now=1001.0), "GENEVA_CLIENTHELLO_REACHED_RU")

        no_traffic = self._base_report(syn=0, target_ch=0, sni_unsplit=0, synack=0, badsum=0)
        with self.assertRaisesRegex(RuntimeError, "NO_TRAFFIC"):
            ev.validate_geneva_report(no_traffic, now=1001.0)

        no_badsum = self._base_report(syn=1, target_ch=1, synack=1, badsum=0)
        with self.assertRaisesRegex(RuntimeError, "GENEVA_BADSUM_NOT_OBSERVED"):
            ev.validate_geneva_report(no_badsum, now=1001.0)

        dropped_ch = self._base_report(syn=1, target_ch=0, sni_unsplit=0, synack=1, badsum=2)
        with self.assertRaisesRegex(RuntimeError, "GENEVA_SENT_CLIENTHELLO_DROPPED"):
            ev.validate_geneva_report(dropped_ch, now=1001.0)

    def test_capture_command_bidirectional_flag(self):
        inbound = obs.capture_command(edge="188.120.254.223", peer=None, bidirectional=False)
        self.assertIn("dst port 443", " ".join(inbound))
        self.assertNotIn("and port 443", " ".join(inbound))

        bidir = obs.capture_command(edge="188.120.254.223", peer="185.137.178.123", bidirectional=True)
        joined = " ".join(bidir)
        self.assertIn("and host 188.120.254.223 and port 443 and host 185.137.178.123", joined)

    def test_remote_run_forwards_geneva_flags_and_main_uses_geneva_validator(self):
        remote = object.__new__(adapter.Remote)
        remote.window = 8
        remote.prefix_timeout = 12
        remote.experiment_mode = "geneva"
        remote.geneva_variant = "ack-desync"
        remote.geneva_repeats = 3
        calls = []
        remote.call = lambda role, command, **kw: calls.append((role, command)) or "ok"

        remote.run("ru", "start", peer="all")
        self.assertEqual(len(calls), 1)
        cmd = calls[0][1]
        self.assertIn("--experiment-mode geneva", cmd)
        self.assertIn("--geneva-variant ack-desync", cmd)
        self.assertIn("--geneva-repeats 3", cmd)

        report = self._base_report()
        actions = []

        class FakeRemote:
            def preflight(self, role):
                pass

            def stage_files(self, role):
                pass

            def run(self, role, action, peer=None):
                actions.append((role, action, peer))
                return "ok"

            def verify_health(self):
                pass

            def active_window(self, seconds, *, clamp_mode="on", unclamped_seconds=540, experiment_mode="window"):
                actions.append(("window", seconds, clamp_mode, experiment_mode))

            def collect_evidence(self, *, final=False, require_success=False):
                actions.append(("evidence", final, require_success))
                return report

            def reset(self, role):
                pass

        with patch.object(adapter, "Remote", return_value=FakeRemote()) as rem_cls, \
             patch.object(adapter, "validate_geneva_report", return_value="GENEVA_CLIENTHELLO_REACHED_RU") as val_fn, \
             patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "MNEBY_META_V30_APPROVED": adapter.APPROVAL}), \
             patch.object(adapter.signal, "signal"):
            adapter.main([
                "--mode", "activate",
                "--phone-ip", "all",
                "--minutes", "5",
                "--experiment-mode", "geneva",
                "--geneva-variant", "ack-desync",
                "--geneva-repeats", "3",
            ])

        rem_cls.assert_called_once_with(
            experiment_mode="geneva",
            geneva_variant="ack-desync",
            geneva_repeats=3,
        )
        self.assertIn(("window", 300, "on", "geneva"), actions)
        val_fn.assert_called_once_with(report)
        self.assertNotIn(("ru", "set-clamp-off", None), actions)
        self.assertNotIn(("ru", "set-clamp-on", None), actions)

    def test_ru_stage_geneva_mode_and_clamp_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "armed").write_text("armed\n")
            (root / "experiment_mode").write_text("geneva")
            with patch.object(ru, "ROOT", root), patch.object(ru, "owner_flag"):
                with self.assertRaisesRegex(RuntimeError, "invalid in geneva"):
                    ru.set_clamp("on")

            fresh_root = Path(d) / "fresh"
            cmds = []
            state = {"timer_armed": False}

            def fake_cmd(argv, **kwargs):
                cmds.append(tuple(argv))
                if argv[0] == "systemd-run" and "rollback" in argv:
                    state["timer_armed"] = True
                if argv[:2] == ["ip", "-j"]:
                    return SimpleNamespace(returncode=0, stdout='[{"dev":"tg-relay"}]')
                if argv[:3] == ["ip", "-4", "-o"]:
                    return SimpleNamespace(returncode=0, stdout="2: ens3    inet 188.120.254.223/32\n")
                if argv[:2] == ["sysctl", "-n"]:
                    return SimpleNamespace(returncode=0, stdout="1\n")
                if argv[:2] == ["ss", "-H"]:
                    port = argv[-1]
                    return SimpleNamespace(returncode=0, stdout=("LISTEN\n" if ":443" in port else ""))
                if argv[:3] == ["nft", "-j", "list"]:
                    return SimpleNamespace(returncode=0, stdout='{"nftables":[]}')
                return SimpleNamespace(returncode=0, stdout="")

            def fake_active(unit):
                if unit == "wg-quick@tg-relay.service":
                    return True
                if unit == "mneby-meta-v26-ru-watchdog.timer":
                    return state["timer_armed"]
                return False

            with patch.object(ru, "ROOT", fresh_root), \
                 patch.object(ru, "owner_flag"), \
                 patch.object(ru, "active", side_effect=fake_active), \
                 patch.object(ru, "table_exists", side_effect=[False, True]), \
                 patch.object(ru, "verify_non_meta_fallback"), \
                 patch.object(ru, "verify_queue_exemption"), \
                 patch.object(ru, "firewall_present", return_value=False), \
                 patch.object(ru, "firewall_install"), \
                 patch.object(ru, "ready_worker", return_value=True), \
                 patch.object(ru, "evidence_ready", return_value=True), \
                 patch.object(ru, "verify_tls_path", return_value=2), \
                 patch.object(ru, "_verify_geneva_sockets"), \
                 patch.object(ru, "cmd", side_effect=fake_cmd):
                ru.start("all", experiment_mode="geneva", geneva_variant="ack-desync", geneva_repeats=3)

            self.assertEqual((fresh_root / "experiment_mode").read_text(), "geneva")
            self.assertEqual((fresh_root / "geneva_variant").read_text(), "ack-desync")
            self.assertEqual((fresh_root / "geneva_repeats").read_text(), "3")
            worker_cmd = next(c for c in cmds if c[0] == "systemd-run" and "--experiment-mode" in c)
            self.assertIn("geneva", worker_cmd)
            self.assertIn("--geneva-variant", worker_cmd)
            self.assertIn("ack-desync", worker_cmd)

    def test_termux_script_and_schedule_support_geneva_cell_d(self):
        script = runner.generate_termux_script(SimpleNamespace(
            control_sni="yandex.ru",
            edge_ip="188.120.254.223",
            run_id="geneva-test",
            operator="mts",
            network_type="mobile",
            attempts=3,
            pause=1,
        ))
        self.assertIn('if [ "$PHASE" = "geneva" ]; then', script)
        self.assertIn('run_one B "$CONTROL_SNI" "вкл" "$i"', script)
        self.assertIn('run_one D "i.instagram.com" "вкл" "$i"', script)
        sched = runner.build_schedule(cells=("B", "D"), attempts=2, control_sni="yandex.ru")
        self.assertEqual([(s.cell, s.attempt, s.sni, s.clamp) for s in sched], [
            ("B", 1, "yandex.ru", "вкл"),
            ("D", 1, "i.instagram.com", "вкл"),
            ("B", 2, "yandex.ru", "вкл"),
            ("D", 2, "i.instagram.com", "вкл"),
        ])


if __name__ == "__main__":
    unittest.main()
