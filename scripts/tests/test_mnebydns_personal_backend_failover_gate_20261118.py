import copy
import json
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from mnebydns_personal_backend_failover_gate_20261118 import assess, ROUTES

def evidence():
    def node(port, p95):
        return {
            "port":port,
            "ca_verified_personal_tls":"pass",
            "failure_domain":"ru188-single-awg-tunnel",
            "ingress_id":"de89-personal-sni",
            "authorization":{
                "active_smart_dns":"pass", "active_vpn_origin":"pass",
                "unknown_sni_denied":"pass", "expired_denied":"pass",
                "revoked_denied":"pass",
            },
            "routes":copy.deepcopy(ROUTES),
            "timing":{"sample_count":20,"dns_p50_ms":50,"dns_p95_ms":p95},
        }
    return {
        "schema_version":1,
        "scope":"personal_dot_authenticated",
        "age_seconds":60,
        "identity_source":"dedicated_service_profile",
        "controls":{"legacy_public_fallback":False,
                    "credential_exported_to_ci":False,
                    "subscriber_policy_change":False},
        "primary":node(8858,100),
        "standby":node(8856,112),
        "client":{"wifi":"pass","cellular":"pass"},
        "drills":{"isolated_backend_failure":"pass","rollback":"pass",
                  "no_legacy_fallback":"pass"},
    }

class PersonalFailoverTests(unittest.TestCase):
    def test_empty_evidence_fails_closed(self):
        out=assess({"schema_version":1})
        self.assertFalse(out["personal_backend_process_fallback_candidate"])
        self.assertFalse(out["independent_dns_ha_candidate"])
        self.assertFalse(out["production_switch_enabled"])
        self.assertTrue(out["missing_or_failed_gates"])

    def test_full_supplied_evidence_can_only_be_offline_candidate(self):
        out=assess(evidence())
        self.assertTrue(out["personal_backend_process_fallback_candidate"])
        self.assertFalse(out["independent_dns_ha_candidate"])
        self.assertFalse(out["production_switch_enabled"])
        self.assertEqual(out["checked_policy_count"],2)
        self.assertEqual(out["missing_or_failed_gates"],[])

    def test_missing_service_identity_fails_closed(self):
        data=evidence()
        data["identity_source"]="customer_bearer"
        self.assertIn("dedicated_service_profile_unverified",
                      assess(data)["missing_or_failed_gates"])

    def test_legacy_fallback_never_counts_as_personal(self):
        data=evidence()
        data["controls"]["legacy_public_fallback"]=True
        out=assess(data)
        self.assertFalse(out["personal_backend_process_fallback_candidate"])
        self.assertIn("legacy_anonymous_fallback_not_explicitly_closed",
                      out["missing_or_failed_gates"])

    def test_revoked_or_expired_identity_must_fail_on_both(self):
        for check in ("revoked_denied","expired_denied","unknown_sni_denied"):
            data=evidence()
            data["standby"]["authorization"][check]="fail"
            out=assess(data)
            self.assertFalse(out["personal_backend_process_fallback_candidate"])
            self.assertIn("standby_"+check+"_unverified",out["missing_or_failed_gates"])

    def test_both_video_route_modes_must_be_preserved(self):
        data=evidence()
        data["standby"]["routes"]["smart_dns"]["googlevideo_a"]="direct"
        out=assess(data)
        self.assertFalse(out["personal_backend_process_fallback_candidate"])
        self.assertIn("standby_smart_dns_googlevideo_a_not_equivalent",
                      out["missing_or_failed_gates"])
        data=evidence()
        data["standby"]["routes"]["vpn_origin"]["googlevideo_a"]="mapped"
        self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])

    def test_aaaa_and_https_bypass_prevention(self):
        for rr in ("googlevideo_aaaa","googlevideo_https"):
            data=evidence()
            data["standby"]["routes"]["smart_dns"][rr]="direct"
            self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])

    def test_standby_latency_is_a_hard_gate(self):
        data=evidence()
        data["standby"]["timing"]["dns_p95_ms"]=250
        out=assess(data)
        self.assertFalse(out["personal_backend_process_fallback_candidate"])
        self.assertIn("standby_latency_budget_exceeded",out["missing_or_failed_gates"])

    def test_nan_bool_and_small_samples_cannot_pass(self):
        for value in (float("nan"),float("inf"),True,-5,0):
            data=evidence()
            data["standby"]["timing"]["dns_p95_ms"]=value
            self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])
        for count in (True,0,9,1001):
            data=evidence()
            data["standby"]["timing"]["sample_count"]=count
            self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])

    def test_stale_data_and_missing_cellular_drill_fails_closed(self):
        data=evidence()
        data["age_seconds"]=901
        self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])
        data=evidence()
        data["client"]["cellular"]="unverified"
        self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])
        data=evidence()
        data["drills"]["rollback"]="unverified"
        self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])

    def test_ports_expected_and_distinct(self):
        data=evidence()
        data["standby"]["port"]=8858
        self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])
        data=evidence()
        data["standby"]["port"]=True
        self.assertFalse(assess(data)["personal_backend_process_fallback_candidate"])

    def test_result_does_not_print_personal_identifier_or_ip(self):
        data=evidence()
        data["personal_sni"]="sensitive1234.dns.mnebyvpn.site"
        data["primary"]["endpoint"]="192.0.2.37"
        text=json.dumps(assess(data))
        self.assertNotIn(data["personal_sni"],text)
        self.assertNotIn("192.0.2.37",text)

    def test_no_live_network_or_switch_even_on_positive_evidence(self):
        with patch("socket.socket",side_effect=AssertionError("network prohibited")):
            out=assess(evidence())
        self.assertTrue(out["personal_backend_process_fallback_candidate"])
        self.assertFalse(out["production_switch_enabled"])

    def test_wrong_schema_or_invalid_config_rejected(self):
        for data in (None, {}, {"schema_version":2}):
            with self.assertRaises(ValueError):
                assess(data)
        with self.assertRaises(ValueError):
            assess(evidence(),max_p95_ratio=0)

if __name__=="__main__":
    unittest.main()
