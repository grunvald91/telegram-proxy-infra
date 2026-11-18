#!/usr/bin/env python3
"""Fail-closed OFFLINE gate for PERSONAL DoT 8858 -> 8856 backend fallback.

This only assesses redacted operator-provided evidence. It never connects to a
server, reads personal identifiers, issues credentials or switches live traffic.
Even a passing result is NOT authorization for an automatic production cutover.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

AUTH_CHECKS = (
    "active_smart_dns", "active_vpn_origin",
    "active_paid_premium", "paid_expired_premium_denied",
    "paid_quota_exhausted_premium_denied",
    "unknown_sni_denied", "cross_subscriber_sni_denied",
    "expired_denied", "revoked_denied",
)
ROUTES = {
    "smart_dns": {
        "youtube_api_a": "mapped",
        "googlevideo_a": "mapped",
        "googlevideo_aaaa": "nodata",
        "googlevideo_https": "nodata",
    },
    "vpn_origin": {
        "youtube_api_a": "mapped",
        "googlevideo_a": "direct",
        "googlevideo_aaaa": "nodata",
        "googlevideo_https": "nodata",
    },
}
EXPECTED_PORTS = (8858, 8856)

def _pass(obj, name):
    return isinstance(obj, dict) and obj.get(name) == "pass"

def _ms(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    v = float(value)
    return v if math.isfinite(v) and v > 0 else None

def assess(evidence, *, max_age_seconds=900, max_extra_p95_ms=100,
           max_p95_ratio=1.25, max_absolute_p95_ms=350):
    """Return only non-sensitive decisions and reason codes, never raw evidence."""
    if not isinstance(evidence, dict) or evidence.get("schema_version") != 1:
        raise ValueError("unsupported personal failover evidence schema")
    if not (0 < max_age_seconds <= 86400 and
            0 < max_extra_p95_ms <= 5000 and
            1 <= max_p95_ratio <= 5 and
            0 < max_absolute_p95_ms <= 10000):
        raise ValueError("invalid failover performance policy")

    reasons = []
    def need(condition, code):
        if not condition:
            reasons.append(code)
        return bool(condition)

    need(evidence.get("scope") == "personal_dot_authenticated",
         "personal_authenticated_evidence_missing")
    age = evidence.get("age_seconds")
    need(isinstance(age, (int, float)) and not isinstance(age, bool)
         and math.isfinite(age) and 0 <= age <= max_age_seconds,
         "evidence_stale_or_undated")
    need(evidence.get("identity_source") == "dedicated_service_profile",
         "dedicated_service_profile_unverified")

    controls = evidence.get("controls")
    need(isinstance(controls, dict) and controls.get("legacy_public_fallback") is False,
         "legacy_anonymous_fallback_not_explicitly_closed")
    need(isinstance(controls, dict) and controls.get("credential_exported_to_ci") is False,
         "service_credentials_not_proven_private")
    need(isinstance(controls, dict) and controls.get("subscriber_policy_change") is False,
         "subscriber_policy_must_remain_unchanged")

    primary = evidence.get("primary") if isinstance(evidence.get("primary"), dict) else {}
    standby = evidence.get("standby") if isinstance(evidence.get("standby"), dict) else {}
    samples = []
    nodes = (("primary", primary), ("standby", standby))

    ports_valid = (
        type(primary.get("port")) is int and type(standby.get("port")) is int
        and (primary["port"], standby["port"]) == EXPECTED_PORTS
    )
    need(ports_valid, "primary_standby_ports_not_verified")

    # A handful of matching answers cannot prove identical subscription and
    # routing behavior. Require full content hashes of the gateway, route
    # policy and SQL status function as separate independent evidence.
    for artifact in ("gateway_build_sha256", "route_policy_sha256",
                     "owner_status_function_sha256"):
        hashes = [node.get(artifact) for _, node in nodes]
        complete = all(isinstance(value,str)
                       and re.fullmatch(r"[0-9a-f]{64}",value)
                       for value in hashes)
        need(complete and hashes[0] == hashes[1],
             artifact + "_not_proven_identical")

    for label, node in nodes:
        need(_pass(node, "ca_verified_personal_tls"),
             f"{label}_personal_tls_not_verified")
        auth = node.get("authorization")
        for check in AUTH_CHECKS:
            need(_pass(auth, check), f"{label}_{check}_unverified")
        policies = node.get("routes")
        for policy, expectations in ROUTES.items():
            entries = policies.get(policy) if isinstance(policies, dict) else None
            for domain, expected in expectations.items():
                need(isinstance(entries, dict) and entries.get(domain) == expected,
                     f"{label}_{policy}_{domain}_not_equivalent")
        timing = node.get("timing") if isinstance(node.get("timing"), dict) else {}
        count = timing.get("sample_count")
        p50, p95 = _ms(timing.get("dns_p50_ms")), _ms(timing.get("dns_p95_ms"))
        valid = (type(count) is int and 10 <= count <= 1000 and
                 p50 is not None and p95 is not None and p95 >= p50)
        need(valid, f"{label}_authenticated_dns_samples_missing")
        if valid:
            samples.append((p50,p95))

    if len(samples) == 2:
        primary_p95, standby_p95 = samples[0][1], samples[1][1]
        need(standby_p95 <= primary_p95 * max_p95_ratio and
             standby_p95 - primary_p95 <= max_extra_p95_ms and
             standby_p95 <= max_absolute_p95_ms,
             "standby_latency_budget_exceeded")

    drills = evidence.get("drills")
    for check in ("isolated_backend_failure", "rollback", "no_legacy_fallback"):
        need(_pass(drills,check), f"{check}_drill_unverified")
    client = evidence.get("client")
    for check in ("wifi", "cellular"):
        need(_pass(client,check), f"personal_{check}_path_unverified")

    # Process failover is NOT independent DNS high availability. Two backend
    # ports on the same RU node and TG tunnel share a failure domain.
    process_candidate = not reasons
    primary_zone, standby_zone = primary.get("failure_domain"), standby.get("failure_domain")
    independent_ingress = (isinstance(primary_zone,str) and bool(primary_zone)
                           and isinstance(standby_zone,str) and bool(standby_zone)
                           and primary_zone != standby_zone
                           and primary.get("ingress_id") != standby.get("ingress_id")
                           and all(isinstance(n.get("ingress_id"),str)
                                   and n["ingress_id"] for _,n in nodes))
    return {
        "schema_version": 1,
        "assessment_kind": "offline_operator_supplied_evidence_only",
        "personal_backend_process_fallback_candidate": process_candidate,
        "independent_dns_ha_candidate": bool(process_candidate and independent_ingress),
        "production_switch_enabled": False,
        "missing_or_failed_gates": sorted(set(reasons)),
        "checked_policy_count": len(ROUTES),
        "checked_authorization_properties_per_backend": len(AUTH_CHECKS),
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence",required=True,type=Path)
    parser.add_argument("--output",type=Path)
    opt=parser.parse_args()
    data=json.loads(opt.evidence.read_text(encoding="utf-8"))
    result=assess(data)
    payload=json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n"
    if opt.output:
        opt.output.write_text(payload,encoding="utf-8")
    print(payload,end="")

if __name__=="__main__":
    main()
