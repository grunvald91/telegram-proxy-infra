"""Offline tests for one-node, read-only SNI and HTTP header sampling."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mnebydns_onnode_service_probe as p
import mnebydns_reliability_monitor as main_monitor


class HttpClassificationTests(unittest.TestCase):
    def test_status_lines(self):
        for raw, expected in (
            (b"HTTP/1.1 200 OK\r\nX: value\r\n", 200),
            (b"HTTP/1.0 403 Forbidden\r\n", 403),
            (b"HTTP/1.1 302 Found\r\n", 302),
            (b"HTTP/2 200 OK\r\n", None),
            (b"not HTTP\r\n", None),
            (b"", None),
            (b"HTTP/1.1 999 Invalid\r\n", None),
            (b"HTTP/1.1 200 " + b"x" * 145 + b"\r\n", None),
        ):
            with self.subTest(raw=raw[:25]):
                self.assertEqual(p.parse_status(raw), expected)

    def test_http_errors_are_not_mislabeled_as_application_outages(self):
        self.assertEqual(p.categorize_http(200), "http_response_2xx_3xx")
        self.assertEqual(p.categorize_http(302), "http_response_2xx_3xx")
        self.assertEqual(p.categorize_http(403), "http_response_restricted_or_path_specific")
        self.assertEqual(p.categorize_http(451), "http_response_restricted_or_path_specific")
        self.assertEqual(p.categorize_http(404), "http_response_restricted_or_path_specific")
        self.assertEqual(p.categorize_http(429), "http_rate_limited")
        self.assertEqual(p.categorize_http(503), "http_response_5xx_unverified")
        self.assertEqual(p.categorize_http(None), "unknown")

    def test_targets_match_established_registry_and_do_not_claim_microsoft(self):
        expected = {(x.name, x.hostname) for x in main_monitor.SERVICES if x.route == "proxy"}
        actual = {(label, host) for label, host, route in p.TARGETS if route == "proxy"}
        self.assertEqual(actual, expected)
        self.assertIn(("microsoft", "copilot.microsoft.com", "observe"), p.TARGETS)


class FakePlain:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout


class FakeTls:
    def __init__(self, response):
        self.response = response
        self.sent = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def version(self):
        return "TLSv1.3"

    def sendall(self, data):
        self.sent = data

    def recv(self, n):
        result = self.response[:n]
        self.response = self.response[n:]
        return result


class FakeContext:
    def __init__(self, tls):
        self.tls = tls
        self.sni = None
        self.alpn = None

    def set_alpn_protocols(self, protocols):
        self.alpn = protocols

    def wrap_socket(self, sock, server_hostname):
        self.sni = server_hostname
        return self.tls


class ProbeTests(unittest.TestCase):
    def test_pinned_loopback_original_sni_and_verified_http(self):
        tls = FakeTls(b"HTTP/1.1 302 Found\r\nLocation: /login\r\n")
        ctx = FakeContext(tls)
        with (patch.object(p.socket, "create_connection", return_value=FakePlain()) as sock,
              patch.object(p.ssl, "create_default_context", return_value=ctx)):
            record = p.probe("claude_web", "claude.ai", "proxy")
        sock.assert_called_once_with(("127.0.0.1", 443), timeout=4.0)
        self.assertEqual(ctx.sni, "claude.ai")
        self.assertEqual(ctx.alpn, ["http/1.1"])
        self.assertIn(b"Host: claude.ai\r\n", tls.sent)
        self.assertIn(b"Connection: close\r\n", tls.sent)
        self.assertNotIn(b"Cookie:", tls.sent)
        self.assertEqual(record["tls"], "pass")
        self.assertEqual(record["http"], "http_response_2xx_3xx")
        self.assertEqual(record["http_status"], 302)

    def test_tls_verify_failure_is_fail_not_200(self):
        class BadContext(FakeContext):
            def wrap_socket(self, *_args, **_kwargs):
                raise p.ssl.SSLCertVerificationError("no verified certificate")
        with (patch.object(p.socket, "create_connection", return_value=FakePlain()),
              patch.object(p.ssl, "create_default_context", return_value=BadContext(None))):
            result = p.probe("gemini", "gemini.google.com", "proxy")
        self.assertEqual(result["tls"], "fail")
        self.assertEqual(result["http"], "not_checked")
        self.assertEqual(result["error_class"], "SSLCertVerificationError")

    def test_http_403_is_not_reported_as_tls_failure(self):
        with (patch.object(p.socket, "create_connection", return_value=FakePlain()),
              patch.object(p.ssl, "create_default_context",
                           return_value=FakeContext(FakeTls(b"HTTP/1.1 403 Forbidden\r\n")))):
            result = p.probe("x", "x.com", "proxy")
        self.assertEqual(result["tls"], "pass")
        self.assertEqual(result["http"], "http_response_restricted_or_path_specific")

    def test_unapproved_host_and_workers_fail_before_network_access(self):
        with patch.object(p.socket, "create_connection", side_effect=AssertionError("network use forbidden")):
            with self.assertRaises(ValueError):
                p.probe("other", "attacker.invalid", "proxy")
            with self.assertRaises(ValueError):
                p.probe("claude_web", "claude.ai", "proxy", timeout=50)
            with self.assertRaises(ValueError):
                p.collect((("bad", "attacker.invalid", "proxy"),))
            with self.assertRaises(ValueError):
                p.collect(worker_count=0)

    def test_collection_proves_neither_client_availability_nor_egress(self):
        with patch.object(p, "probe", side_effect=lambda label, host, route: {
            "service": label, "expected": route, "tls": "pass",
            "http": "http_response_restricted_or_path_specific", "http_status": 403,
            "elapsed_ms": 10.0, "error_class": None,
        }):
            report = p.collect(p.TARGETS[:2], worker_count=1)
        self.assertEqual(report["tls_verified"], 2)
        self.assertEqual(report["http_2xx_3xx"], 0)
        self.assertFalse(report["client_end_to_end_verified"])
        self.assertFalse(report["per_service_egress_verified"])
        self.assertFalse(report["automatic_failover_enabled"])
        self.assertFalse(report["data_plane_mutation"])
        self.assertEqual(report["vantage"], "foreign_vps_loopback_443_not_end_user")


if __name__ == "__main__":
    unittest.main()
