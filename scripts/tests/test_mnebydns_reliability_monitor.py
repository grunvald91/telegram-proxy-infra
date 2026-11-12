import importlib.util
import ipaddress
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "mnebydns_reliability_monitor.py"
spec = importlib.util.spec_from_file_location("reliability", SRC)
m = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class DnsTest(unittest.TestCase):
    def fixture(self, host="claude.ai", qtype=1, ip="203.0.113.2", rcode=0):
        txid = 321
        question = m._fqdn(host) + struct.pack("!HH", qtype, 1)
        raw = ipaddress.ip_address(ip).packed
        record = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 20, len(raw)) + raw
        packet = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, 1, 0, 0) + question + record
        return packet, txid

    def test_dns_a_and_aaaa_round_trip(self):
        for qtype, ip in [(1, "203.0.113.2"), (28, "2001:db8::1")]:
            msg, txid = self.fixture(qtype=qtype, ip=ip)
            self.assertEqual(m.decode_dns_response(msg, "claude.ai", qtype, txid), m.DnsAnswer(0, (ip,)))

    def test_reject_spoofed_header_question_and_compression_loop(self):
        msg, txid = self.fixture()
        with self.assertRaisesRegex(ValueError, "header"):
            m.decode_dns_response(msg, "claude.ai", 1, txid + 1)
        with self.assertRaisesRegex(ValueError, "question mismatch"):
            m.decode_dns_response(msg, "example.org", 1, txid)
        self.assertRaisesRegex(ValueError, "pointer", m._read_name, b"\xc0\x00", 0)
        self.assertRaisesRegex(ValueError, "truncated", m.decode_dns_response, msg[:-2], "claude.ai", 1, txid)

    def test_expected_modes_do_not_confuse_observe_with_success(self):
        answer = m.DnsAnswer(0, ("203.0.113.2",))
        self.assertEqual(m.evaluate_route("proxy", answer, "203.0.113.2"), "pass")
        self.assertEqual(m.evaluate_route("direct", answer, "203.0.113.2"), "fail")
        self.assertEqual(m.evaluate_route("observe", answer, "203.0.113.2"), "observe_proxy")
        self.assertEqual(m.evaluate_route("proxy", m.DnsAnswer(2, ()), "203.0.113.2"), "fail")
        self.assertEqual(m.evaluate_route("observe", m.DnsAnswer(2, ()), "203.0.113.2"), "unknown")

    def test_no_mutation_and_tls_not_full_end_user_success(self):
        asked = []
        def dns(host, _):
            asked.append(host)
            return m.DnsAnswer(0, ("203.0.113.2",))
        def tls(_, host):
            self.assertEqual(host, "claude.ai")
            return 41.5
        records = (m.Service("verified", "claude.ai", "proxy", True),
                   m.Service("unknown", "threads.net", "observe", False))
        with patch.object(m.socket, "create_connection", side_effect=AssertionError("unexpected actual network")):
            report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "match",
                               query=dns, tls_probe=tls, services=records)
        self.assertEqual(report["critical_failures"], 0)
        self.assertFalse(report["route_fallback_enabled"])
        self.assertEqual(asked, ["claude.ai", "claude.ai", "threads.net", "threads.net"])
        self.assertEqual(report["services"][0]["tls"], "pass")
        self.assertEqual(report["services"][0]["ipv6"], "possible_direct_bypass")
        self.assertEqual(report["services"][1]["dns"], "observe_proxy")

    def test_egress_mismatch_or_failed_expected_route_is_reported(self):
        records = (m.Service("bad", "claude.ai", "proxy", False),)
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "mismatch",
                           query=lambda *_: m.DnsAnswer(0, ("192.0.2.1",)), services=records)
        self.assertEqual(report["critical_failures"], 2)
        self.assertEqual(report["services"][0]["dns"], "fail")

    def test_failed_public_ingress_with_working_control_flags_target_only(self):
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "match",
                           query=lambda *_: m.DnsAnswer(0, ("203.0.113.2",)),
                           tls_probe=lambda *_: self.fail("TLS must be skipped"),
                           services=(m.Service("claude", "claude.ai", "proxy", True),),
                           ingress_tcp="fail", control_tcp="pass", ingress_tcp_error="TimeoutError")
        self.assertEqual(report["critical_failures"], 0)
        self.assertTrue(report["external_tcp_path_warning"])
        self.assertEqual(report["health_classification"], "dns_routes_observed_transport_unverified")
        self.assertFalse(report["client_end_to_end_verified"])
        self.assertEqual(report["transport_warning_count"], 1)
        self.assertEqual(report["services"][0]["tls"], "skipped_ingress_tcp_unreachable")

    def test_failed_public_ingress_and_control_is_uncertain_not_server_down(self):
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "match",
                           query=lambda *_: m.DnsAnswer(0, ("203.0.113.2",)),
                           services=(m.Service("claude", "claude.ai", "proxy", False),),
                           ingress_tcp="fail", control_tcp="fail")
        self.assertEqual(report["critical_failures"], 0)

    def test_reject_unrelated_answer_owner_instead_of_false_dns_pass(self):
        host = "claude.ai"
        question = m._fqdn(host) + struct.pack("!HH", 1, 1)
        ipv4 = ipaddress.ip_address("203.0.113.2").packed
        record = m._fqdn("unrelated.example") + struct.pack("!HHIH", 1, 1, 30, 4) + ipv4
        pkt = struct.pack("!HHHHHH", 321, 0x8180, 1, 1, 0, 0) + question + record
        answer = m.decode_dns_response(pkt, host, 1, 321)
        self.assertEqual(answer.addresses, ())
        self.assertEqual(m.evaluate_route("proxy", answer, "203.0.113.2"), "fail")

    def test_valid_cname_chain_keeps_answer_owner_validation(self):
        question = m._fqdn("claude.ai") + struct.pack("!HH", 1, 1)
        cname = m._fqdn("edge.example")
        cname_record = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 30, len(cname)) + cname
        ip = ipaddress.ip_address("203.0.113.2").packed
        target_a = m._fqdn("edge.example") + struct.pack("!HHIH", 1, 1, 30, 4) + ip
        unrelated = m._fqdn("unrelated.example") + struct.pack("!HHIH", 1, 1, 30, 4) + ipaddress.ip_address("192.0.2.3").packed
        packet = struct.pack("!HHHHHH", 321, 0x8180, 1, 3, 0, 0) + question + cname_record + target_a + unrelated
        self.assertEqual(m.decode_dns_response(packet, "claude.ai", 1, 321).addresses, ("203.0.113.2",))

    def test_truncated_bit_and_cname_cycle_fail_closed(self):
        pkt, txid = self.fixture()
        truncated = pkt[:2] + struct.pack("!H", 0x8380) + pkt[4:]
        with self.assertRaisesRegex(ValueError, "header"):
            m.decode_dns_response(truncated, "claude.ai", 1, txid)
        q = m._fqdn("claude.ai") + struct.pack("!HH", 1, 1)
        self_target = b"\xc0\x0c"
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 10, len(self_target)) + self_target
        cyclic = struct.pack("!HHHHHH", 321, 0x8180, 1, 1, 0, 0) + q + rr
        with self.assertRaisesRegex(ValueError, "CNAME cycle"):
            m.decode_dns_response(cyclic, "claude.ai", 1, 321)

    def test_unverified_status_even_when_dns_is_correct(self):
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "unknown",
                           query=lambda *_: m.DnsAnswer(0, ("203.0.113.2",)),
                           tls_probe=lambda *_: 12.0,
                           services=(m.Service("claude", "claude.ai", "proxy", True),),
                           ingress_tcp="pass", control_tcp="pass")
        self.assertEqual(report["critical_failures"], 0)
        self.assertEqual(report["health_classification"], "dns_routes_observed_transport_unverified")
        self.assertFalse(report["client_end_to_end_verified"])

    def test_transport_tls_failure_is_reported_separately(self):
        def unavailable(*_):
            raise TimeoutError("test transport failure")
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "match",
                           query=lambda *_: m.DnsAnswer(0, ("203.0.113.2",)),
                           tls_probe=unavailable,
                           services=(m.Service("claude", "claude.ai", "proxy", True),),
                           ingress_tcp="pass", control_tcp="pass")
        self.assertEqual(report["transport_warning_count"], 1)
        self.assertEqual(report["services"][0]["tls"], "fail")
        self.assertEqual(report["critical_failures"], 0)
        self.assertNotEqual(report["health_classification"], "dns_routes_and_public_transport_observed")

    def test_tcp_control_retries_ipv4_only_and_rejects_invalid_attempts(self):
        attempts = []
        class FakeSocket:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def settimeout(self, timeout):
                self.timeout = timeout
            def connect(self, endpoint):
                attempts.append(endpoint)
                if len(attempts) == 1:
                    raise TimeoutError("first probe lost")
        with patch.object(m.socket, "socket", side_effect=lambda family, kind: (
                self.assertEqual(family, m.socket.AF_INET) or
                self.assertEqual(kind, m.socket.SOCK_STREAM) or FakeSocket())):
            result = m.tcp_reachable("example.org", attempts=2)
        self.assertEqual(result, ("pass", None))
        self.assertEqual(attempts, [("example.org", 443), ("example.org", 443)])
        with self.assertRaisesRegex(ValueError, "attempts"):
            m.tcp_reachable("example.org", attempts=0)

    def test_incomplete_observations_remain_unverified(self):
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "match",
                           query=lambda *_: m.DnsAnswer(2, ()),
                           services=(m.Service("unknown", "threads.net", "observe", False),),
                           ingress_tcp="pass", control_tcp="pass")
        self.assertEqual(report["critical_failures"], 0)
        self.assertEqual(report["health_classification"], "dns_routes_observed_transport_unverified")

    def test_direct_control_route_skips_tls(self):
        calls = []
        report = m.monitor("203.0.113.3", "dns.example.org", "203.0.113.2", "unknown",
                           query=lambda *_: m.DnsAnswer(0, ("192.0.2.1",)),
                           tls_probe=lambda *_: calls.append("tls"),
                           services=(m.Service("ordinary", "example.org", "direct", True),))
        self.assertEqual(report["critical_failures"], 0)
        self.assertEqual(calls, [])
        self.assertEqual(report["services"][0]["tls"], "not_checked")


if __name__ == "__main__":
    unittest.main()
