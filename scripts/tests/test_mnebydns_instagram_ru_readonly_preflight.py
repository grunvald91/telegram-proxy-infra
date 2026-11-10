#!/usr/bin/env python3
"""Mocked tests of RU VPS read-only preflight: never connect to a VPS."""
import contextlib
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "mnebydns_instagram_ru_readonly_preflight.py"
spec = importlib.util.spec_from_file_location("ru_preflight", SOURCE)
pre = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pre)


def fake_commands(argv, **kwargs):
    joined = " ".join(argv)
    if argv[:4] == ["ip", "-o", "-4", "addr"]:
        return SimpleNamespace(returncode=0, stdout="2: eth0 inet 188.120.254.223/24\n")
    if argv[:3] == ["ss", "-H", "-lnt"]:
        return SimpleNamespace(returncode=0, stdout="LISTEN 0 128 188.120.254.223:443 0.0.0.0:*\n")
    if argv[:2] == ["iptables", "--version"]:
        return SimpleNamespace(returncode=0, stdout="iptables v1.8.10 (nf_tables)\n")
    if argv[:5] == ["iptables", "-w", "-t", "mangle", "-S"]:
        return SimpleNamespace(returncode=0, stdout="-P OUTPUT ACCEPT\n")
    if argv[:3] == ["nft", "list", "ruleset"]:
        return SimpleNamespace(returncode=0, stdout="table ip filter { chain OUTPUT { type filter hook output priority 0; policy accept; } }")
    if argv[:2] == ["systemctl", "is-active"]:
        return SimpleNamespace(returncode=3, stdout="inactive\n")
    raise AssertionError(f"Unexpected read-only call: {joined}")


class PreflightTests(TestCase):
    def run_preflight(self, occupied=False, queue_active=False):
        def command(argv, **kwargs):
            ans = fake_commands(argv, **kwargs)
            if occupied and argv[:3] == ["ss", "-H", "-lnt"]:
                ans.stdout += "LISTEN 0 128 188.120.254.223:18443 0.0.0.0:*\n"
            return ans

        original_exists = Path.exists
        original_read = Path.read_text

        def exists(path):
            if str(path) in ("/proc/net/netfilter/nfnetlink_queue",
                             "/proc/sys/net/ipv4/tcp_window_scaling"):
                return True
            return original_exists(path)

        def read(path, *args, **kwargs):
            if str(path) == "/proc/net/netfilter/nfnetlink_queue":
                return "211 0 0\n" if queue_active else "2 0 0\n"
            if str(path) == "/proc/sys/net/ipv4/tcp_window_scaling":
                return "1\n"
            return original_read(path, *args, **kwargs)

        buf = io.StringIO()
        with patch.object(pre, "command", side_effect=command), \
             patch.object(pre.ctypes.util, "find_library", return_value="libnetfilter_queue.so.1"), \
             patch.object(pre.shutil, "which", return_value="/usr/bin/fake"), \
             patch.object(Path, "exists", exists), \
             patch.object(Path, "read_text", read), \
             contextlib.redirect_stdout(buf):
            code = pre.main()
        return code, buf.getvalue()

    def test_clean_host_reports_baseline_pass(self):
        code, report = self.run_preflight()
        self.assertEqual(code, 0)
        self.assertIn("canary_tcp_18443_unoccupied=true", report)
        self.assertIn("nfqueue_211_unclaimed=true", report)
        self.assertIn("canary_readonly_preflight=PASS_BASELINE_ONLY", report)

    def test_occupied_port_prevents_canary(self):
        code, report = self.run_preflight(occupied=True)
        self.assertEqual(code, 1)
        self.assertIn("canary_tcp_18443_unoccupied=false", report)
        self.assertIn("canary_readonly_preflight=BLOCKED", report)

    def test_occupied_queue_prevents_canary(self):
        code, report = self.run_preflight(queue_active=True)
        self.assertEqual(code, 1)
        self.assertIn("nfqueue_211_unclaimed=false", report)
        self.assertIn("canary_readonly_preflight=BLOCKED", report)

    def test_report_is_read_only_and_hides_raw_rules(self):
        content = SOURCE.read_text()
        for item in ("iptables -I", "iptables -D", "systemctl start",
                     "systemctl restart", "nft add", "nft delete", "tcpdump"):
            self.assertNotIn(item, content)
        self.assertIn("canary_readonly_preflight", content)


if __name__ == "__main__":
    main()
