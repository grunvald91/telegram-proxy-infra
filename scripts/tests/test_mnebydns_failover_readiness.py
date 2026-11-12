"""Regression checks for the no-switch, offline P1 failover gate."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mnebydns_failover_readiness as gate


def sample():
    def service(p95):
        return {name: {"dns": "pass", "tls": "pass", "app": "pass",
                       "egress_ipv4": "9.9.9.9", "p95_ms": p95}
                for name in gate.PROXIED}
    def node(zone, dns, proxy, p95):
        return {"failure_domain": zone,
                "egress_failure_domain": zone,
                "dns_endpoint": dns, "proxy_endpoint": proxy,
                "dot_tls": "pass", "proxy_tls": "pass", "ordinary_web": "pass",
                "client_vantages": {"cellular": "pass", "wifi": "pass"},
                "services": service(p95)}
    return {
        "schema_version": 1,
        "primary": node("zone-a", "dns-a.example", "proxy-a.example", 100),
        "standby": node("zone-b", "dns-b.example", "proxy-b.example", 110),
        "client": {"dns_fallback_configured_and_tested": "pass",
                   "proxy_fallback_configured_and_tested": "pass"},
        "drills": {"dns_outage": "pass", "proxy_outage": "pass",
                   "rollback": "pass", "stable_exit_after_proxy_outage": "pass"},
    }


class ReadinessTests(unittest.TestCase):
    def test_no_evidence_is_not_healthy(self):
        result = gate.assess({"schema_version": 1})
        self.assertFalse(result["dns_failover_candidate"])
        self.assertFalse(result["proxy_failover_candidate"])
        self.assertFalse(result["production_switch_enabled"])
        self.assertGreater(len(result["reasons"]), 0)

    def test_supplied_full_evidence_only_marks_offline_candidate(self):
        report = gate.assess(sample())
        self.assertTrue(report["dns_failover_candidate"])
        self.assertTrue(report["proxy_failover_candidate"])
        self.assertTrue(report["stable_egress_candidate"])
        self.assertEqual(report["reasons"], [])
        self.assertFalse(report["production_switch_enabled"])
        self.assertEqual(report["checked_proxied_service_count"], len(gate.PROXIED))

    def test_dns_can_be_candidate_without_proxy_ha(self):
        evidence = sample()
        evidence["standby"]["proxy_endpoint"] = ""
        evidence["standby"]["proxy_tls"] = "unknown"
        evidence["standby"]["egress_failure_domain"] = evidence["primary"]["egress_failure_domain"]
        evidence["drills"]["proxy_outage"] = "unknown"
        evidence["client"]["proxy_fallback_configured_and_tested"] = "unknown"
        evidence["drills"]["stable_exit_after_proxy_outage"] = "unknown"
        report = gate.assess(evidence)
        self.assertTrue(report["dns_failover_candidate"])
        self.assertFalse(report["proxy_failover_candidate"])

    def test_same_dns_host_fails_independence_gate(self):
        evidence = sample()
        evidence["standby"]["dns_endpoint"] = evidence["primary"]["dns_endpoint"]
        self.assertFalse(gate.assess(evidence)["dns_failover_candidate"])

    def test_same_failure_domain_blocks_both(self):
        evidence = sample()
        evidence["standby"]["failure_domain"] = evidence["primary"]["failure_domain"]
        report = gate.assess(evidence)
        self.assertFalse(report["dns_failover_candidate"])
        self.assertFalse(report["proxy_failover_candidate"])

    def test_same_egress_failure_domain_blocks_proxy_but_not_dns(self):
        evidence = sample()
        evidence["standby"]["egress_failure_domain"] = evidence["primary"]["egress_failure_domain"]
        report = gate.assess(evidence)
        self.assertTrue(report["dns_failover_candidate"])
        self.assertFalse(report["proxy_failover_candidate"])

    def test_new_public_exit_blocks_both_and_does_not_log_ips(self):
        evidence = sample()
        evidence["standby"]["services"][gate.PROXIED[0]]["egress_ipv4"] = "1.1.1.1"
        report = gate.assess(evidence)
        self.assertFalse(report["dns_failover_candidate"])
        self.assertFalse(report["proxy_failover_candidate"])
        self.assertNotIn("1.1.1.1", json.dumps(report))

    def test_private_or_unknown_exit_cannot_pass(self):
        for value in ("10.0.0.1", "unknown", None, "2001:4860:4860::8888"):
            with self.subTest(value=value):
                evidence = sample()
                evidence["standby"]["services"][gate.PROXIED[0]]["egress_ipv4"] = value
                self.assertFalse(gate.assess(evidence)["dns_failover_candidate"])

    def test_missing_app_evidence_fails_closed(self):
        evidence = sample()
        evidence["standby"]["services"][gate.PROXIED[-1]]["app"] = "unknown"
        report = gate.assess(evidence)
        self.assertFalse(report["dns_failover_candidate"])
        self.assertIn(f"standby_{gate.PROXIED[-1]}_end_to_end_unverified", report["reasons"])

    def test_latency_regression_fails_closed(self):
        evidence = sample()
        evidence["standby"]["services"][gate.PROXIED[0]]["p95_ms"] = 160
        report = gate.assess(evidence)
        self.assertFalse(report["dns_failover_candidate"])
        self.assertFalse(report["latency_budget_candidate"])

    def test_bool_and_nan_are_not_valid_latency(self):
        for value in (True, float("nan"), float("inf"), -1):
            with self.subTest(value=value):
                evidence = sample()
                evidence["standby"]["services"][gate.PROXIED[0]]["p95_ms"] = value
                self.assertFalse(gate.assess(evidence)["dns_failover_candidate"])

    def test_ordinary_web_and_cellular_are_not_optional(self):
        for node, key in (("standby", "ordinary_web"), ("primary", "dot_tls")):
            with self.subTest(node=node, key=key):
                evidence = sample()
                evidence[node][key] = "fail"
                self.assertFalse(gate.assess(evidence)["dns_failover_candidate"])
        evidence = sample()
        evidence["standby"]["client_vantages"]["cellular"] = "unknown"
        self.assertFalse(gate.assess(evidence)["dns_failover_candidate"])

    def test_no_outage_drill_means_no_dns_candidate(self):
        evidence = sample()
        evidence["drills"]["dns_outage"] = "unknown"
        self.assertFalse(gate.assess(evidence)["dns_failover_candidate"])

    def test_invalid_schema_or_policy_rejected(self):
        with self.assertRaises(ValueError):
            gate.assess({"schema_version": 2})
        with self.assertRaises(ValueError):
            gate.assess(None)
        with self.assertRaises(ValueError):
            gate.assess(sample(), max_latency_ratio=0)

    def test_no_network_access_or_route_mutation(self):
        with patch("socket.socket", side_effect=AssertionError("network prohibited")):
            self.assertTrue(gate.assess(sample())["dns_failover_candidate"])


if __name__ == "__main__":
    unittest.main()
