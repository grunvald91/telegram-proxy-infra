#!/usr/bin/env python3
"""Fake-libnetfilterqueue setup tests; no root required."""
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, mock, main

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import mnebydns_nfq_failopen as nfq


class FakeLib:
    def __init__(self, fail_at):
        self.calls = []
        self.fail_at = fail_at

    def __getattr__(self, key):
        if key in ("nfq_open", "nfq_create_queue"):
            def create(*args):
                self.calls.append(key)
                return 123
            return create
        def invoke(*args):
            self.calls.append(key)
            if key == self.fail_at:
                return -1
            if key == "nfq_fd":
                return -1
            return 0
        return invoke


class FailOpenTests(TestCase):
    def test_sets_fail_open_and_maxlen_before_enabling_rule(self):
        fake = FakeLib("nfq_fd")
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "ready")
            with mock.patch.object(nfq, "load_library", return_value=fake):
                with self.assertRaisesRegex(RuntimeError, "nfq_fd failed"):
                    nfq.run_queue(211, lambda p: p, ready_file=marker)
            self.assertFalse(Path(marker).exists())
            self.assertEqual(fake.calls[:5], [
                "nfq_open", "nfq_create_queue", "nfq_set_mode",
                "nfq_set_queue_flags", "nfq_set_queue_maxlen"
            ])

    def test_refuses_to_start_without_fail_open_support(self):
        fake = FakeLib("nfq_set_queue_flags")
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "ready")
            with mock.patch.object(nfq, "load_library", return_value=fake):
                with self.assertRaisesRegex(OSError, "FAIL_OPEN"):
                    nfq.run_queue(211, lambda p: p, ready_file=marker)
            self.assertFalse(Path(marker).exists())
            self.assertNotIn("nfq_fd", fake.calls)
            self.assertIn("nfq_destroy_queue", fake.calls)
            self.assertIn("nfq_close", fake.calls)

    def test_parent_death_signal_refuses_orphan(self):
        with mock.patch.object(nfq.os, "getppid", return_value=1):
            with self.assertRaisesRegex(RuntimeError, "orphaned"):
                nfq.arm_parent_death_signal()

    def test_parent_death_signal_arms_before_work(self):
        from types import SimpleNamespace
        prctl = mock.Mock(return_value=0)
        with mock.patch.object(nfq.os, "getppid", side_effect=[321, 321]):
            with mock.patch.object(nfq.C, "CDLL", return_value=SimpleNamespace(prctl=prctl)):
                nfq.arm_parent_death_signal()
        prctl.assert_called_once_with(1, nfq.signal.SIGTERM, 0, 0, 0)

    def test_missing_native_library_is_explicit_error(self):
        with mock.patch.object(nfq.C.util, "find_library", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "not installed"):
                nfq.load_library()


if __name__ == "__main__":
    main()
