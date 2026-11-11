#!/usr/bin/env python3
"""Synthetic-only regression checks for read-only Meta routing evidence gate."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from meta_v12_routing_gate import a_de_count, classify, parse
from meta_v12_ru_de_readonly import metric_host

DIRECT_A = "RCODE0_A_DE0_A_RU0_A_OTHER1_AAAA0_CNAME1_HTTPS0_SVCB0"
DE_A = "RCODE0_A_DE1_A_RU0_A_OTHER0_AAAA0_CNAME0_HTTPS0_SVCB0"
AAAA = "RCODE0_A_DE0_A_RU0_A_OTHER0_AAAA1_CNAME1_HTTPS0_SVCB0"

def sample():
    info = {
        "external_dot_A_www_youtube_com": DE_A,
        "no_live_file_changes": "true",
    }
    for host in ("i_instagram_com", "iglite_z_instagram_com"):
        info.update({
            "external_dot_A_" + host: DIRECT_A,
            "external_dot_AAAA_" + host: AAAA,
            "de_nginx_route_" + host + "_count": "0",
            "de_local_ingress_" + host: "CertVerify62_hostname_mismatch",
            "de_to_origin_" + host: "verified_TLSv1_3",
        })
    return info

class EvidenceGateTests(unittest.TestCase):
    def test_current_direct_not_mislabeled_as_proxied(self):
        result = classify(sample())
        self.assertEqual(result["meta_i_instagram_com"], "DIRECT_NOT_PROXY_ROUTED")
        self.assertEqual(result["meta_iglite_z_instagram_com"], "DIRECT_NOT_PROXY_ROUTED")
        self.assertEqual(result["youtube_dns_a_to_de"], "yes")
        self.assertEqual(result["android_end_to_end"], "NOT_TESTED_BY_SERVER_PROBE")

    def test_unsafe_dns_points_to_unmapped_ingress(self):
        info = sample()
        info["external_dot_A_i_instagram_com"] = DE_A
        self.assertEqual(classify(info)["meta_i_instagram_com"], "UNSAFE_DNS_POINTS_AT_MISSING_INGRESS_MAP")

    def test_ingress_config_only_without_dns_route(self):
        info = sample()
        info["de_nginx_route_i_instagram_com_count"] = "1"
        self.assertEqual(classify(info)["meta_i_instagram_com"], "INGRESS_CONFIGURED_BUT_DNS_DIRECT")

    def test_missing_valid_origin_certificate_does_not_pass(self):
        info = sample()
        info["external_dot_A_i_instagram_com"] = DE_A
        info["de_nginx_route_i_instagram_com_count"] = "1"
        self.assertEqual(classify(info)["meta_i_instagram_com"], "UNSAFE_INGRESS_TLS_NOT_VERIFIED")

    def test_candidate_still_does_not_claim_android_success(self):
        info = sample()
        info["external_dot_A_i_instagram_com"] = DE_A
        info["de_nginx_route_i_instagram_com_count"] = "1"
        info["de_local_ingress_i_instagram_com"] = "verified_TLSv1_3"
        status = classify(info)["meta_i_instagram_com"]
        self.assertEqual(status, "PROXY_CANDIDATE_PHONE_E2E_UNVERIFIED")

    def test_incomplete_evidence_rejected(self):
        info = sample()
        del info["de_nginx_route_i_instagram_com_count"]
        with self.assertRaisesRegex(ValueError, "incomplete evidence"):
            classify(info)

    def test_readonly_invariant_required(self):
        info = sample()
        info["no_live_file_changes"] = "false"
        with self.assertRaisesRegex(ValueError, "read-only"):
            classify(info)

    def test_undecodable_dns_status_rejected(self):
        info = sample()
        info["external_dot_A_i_instagram_com"] = "TimeoutError"
        with self.assertRaisesRegex(ValueError, "DoT A"):
            classify(info)

    def test_log_wrappers_are_ignored(self):
        p = parse("### Summary\nexternal_dot_A_i_instagram_com=RCODE0_A_DE0\n\x1b[34mlog=foo\n")
        self.assertEqual(p["external_dot_A_i_instagram_com"], "RCODE0_A_DE0")
        self.assertNotIn("log", p)

    def test_lite_metric_names_match_gate_keys(self):
        self.assertEqual(metric_host("iglite-z.instagram.com"), "iglite_z_instagram_com")
        self.assertEqual(metric_host("i.instagram.com"), "i_instagram_com")

    def test_de_count_strict(self):
        self.assertEqual(a_de_count(DE_A), 1)
        with self.assertRaises(ValueError):
            a_de_count("RCODE2_A_DE1")

if __name__ == "__main__":
    unittest.main()
