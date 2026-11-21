"""Offline regression tests for paired DoT probes. No network or server writes."""
import importlib.util
import pathlib
import socket
import ssl
import struct
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "mnebyvpn_dns_vpn_handoff_monitor.py"
spec = importlib.util.spec_from_file_location("handoff_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeSocket:
    def __init__(self, raw):
        self.raw = raw
    def recv(self, length):
        result, self.raw = self.raw[:min(length, 2)], self.raw[min(length, 2):]
        return result


def packet(txid=0x1234, flags=0x8180, answers=None):
    _, question = probe.frame(txid)
    if answers is None:
        answers = [b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x5d\xb8\xd7\x0e"]
    message = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0) + question + b"".join(answers)
    return FakeSocket(struct.pack("!H", len(message)) + message), question


class TestReadOnlyDoT(unittest.TestCase):
    def test_valid_dns(self):
        sock, question = packet()
        probe.check_dns(sock, 0x1234, question)

    def test_invalid_txid(self):
        sock, question = packet()
        with self.assertRaisesRegex(ValueError, "invalid_dns_reply"):
            probe.check_dns(sock, 0x1235, question)

    def test_servfail_not_success(self):
        sock, question = packet(flags=0x8182)
        with self.assertRaisesRegex(ValueError, "dns_rcode_2"):
            probe.check_dns(sock, 0x1234, question)

    def test_noerror_empty_answer_rejected(self):
        sock, question = packet(answers=[])
        with self.assertRaisesRegex(ValueError, "dns_no_usable_answer"):
            probe.check_dns(sock, 0x1234, question)

    def test_unrelated_a_answer_rejected(self):
        unrelated = b"\x05other\x03org\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        sock, question = packet(answers=[unrelated])
        with self.assertRaisesRegex(ValueError, "dns_no_usable_answer"):
            probe.check_dns(sock, 0x1234, question)

    def test_compression_pointer_cycle_rejected(self):
        cycling = b"\xc0\x1d" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        sock, question = packet(answers=[cycling])
        with self.assertRaisesRegex(ValueError, "invalid_dns_reply"):
            probe.check_dns(sock, 0x1234, question)

    def test_truncated_response_rejected(self):
        sock, question = packet(flags=0x8380)
        with self.assertRaisesRegex(ValueError, "invalid_dns_reply"):
            probe.check_dns(sock, 0x1234, question)

    def test_cname_then_a_accepted(self):
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 11) + b"\x05alias\x03org\x00"
        a = b"\x05alias\x03org\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        sock, question = packet(answers=[cname, a])
        probe.check_dns(sock, 0x1234, question)

    def test_short_frame(self):
        with self.assertRaises(EOFError):
            probe.check_dns(FakeSocket(b"\x00\x20\x01"), 0x1234, b"abc")

    def test_no_overlarge_dns_frame(self):
        with self.assertRaisesRegex(ValueError, "invalid_dns_length"):
            probe.exact(FakeSocket(b""), probe.MAX_DNS_FRAME + 1)

    def test_cert_failure_classification(self):
        exc = ssl.SSLCertVerificationError("certificate verify failed")
        self.assertEqual(probe.classify_error(exc), "certificate")

    def test_refused_failure_classification(self):
        self.assertEqual(probe.classify_error(ConnectionRefusedError()), "refused")
        self.assertEqual(probe.classify_error(socket.timeout()), "timeout")

    def test_multi_sample_thresholds(self):
        ok = {"legacy_dns": {"ok": True}, "personal_tls": {"ok": True}}
        dns = {"legacy_dns": {"ok": False}, "personal_tls": {"ok": True}}
        tls = {"legacy_dns": {"ok": True}, "personal_tls": {"ok": False}}
        self.assertEqual(probe.verdict([ok, ok, ok]), "PASS")
        self.assertEqual(probe.verdict([ok, dns, ok]), "DEGRADED")
        self.assertEqual(probe.verdict([ok, dns, dns]), "FAIL")
        self.assertEqual(probe.verdict([ok, tls, tls]), "FAIL")
        self.assertEqual(probe.verdict([dns]), "FAIL")
        self.assertEqual(probe.verdict([ok, dns]), "DEGRADED")
        self.assertEqual(probe.verdict([dns, dns]), "FAIL")

    def test_no_client_e2e_claim(self):
        self.assertIn("client_wifi_transition_verified", SCRIPT.read_text(encoding="utf8"))
        self.assertIn("authenticated_personal_dns_verified", SCRIPT.read_text(encoding="utf8"))
        self.assertNotIn("systemctl restart", SCRIPT.read_text(encoding="utf8"))


if __name__ == "__main__":
    unittest.main()
