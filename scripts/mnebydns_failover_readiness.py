#!/usr/bin/env python3
"""Offline, fail-closed MNEBYDNS failover readiness assessment.

Consumes operator-supplied evidence, NOT a live client measurement or a
switch authorization. Never connects to or changes a production server.
Never prints exit IPs, endpoint values, customer identifiers or secrets.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
from pathlib import Path

from mnebydns_reliability_monitor import SERVICES

PROXIED = tuple(item.name for item in SERVICES if item.route == "proxy")
CHECKS = ("dot_tls", "proxy_tls", "ordinary_web")
VANTAGES = ("cellular", "wifi")


def _passed(obj: object, key: str) -> bool:
    return isinstance(obj, dict) and obj.get(key) == "pass"


def _valid_public_ipv4(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        addr = ipaddress.ip_address(value)
        return addr.version == 4 and addr.is_global
    except ValueError:
        return False


def _ms(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    return float(value)


def assess(data: object, *, max_latency_ratio: float = 1.25,
           max_extra_ms: float = 100.0) -> dict:
    """A dry-run candidate only: even a passing gate never switches routes."""
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported evidence schema")
    if not 1 <= max_latency_ratio <= 5 or not 0 <= max_extra_ms <= 10000:
        raise ValueError("invalid latency policy")
    primary, standby = data.get("primary"), data.get("standby")
    client, drills = data.get("client"), data.get("drills")
    if not isinstance(primary, dict):
        primary = {}
    if not isinstance(standby, dict):
        standby = {}
    if not isinstance(client, dict):
        client = {}
    if not isinstance(drills, dict):
        drills = {}

    reasons: list[str] = []
    def require(ok: bool, code: str) -> bool:
        if not ok:
            reasons.append(code)
        return ok

    primary_domain = primary.get("failure_domain")
    standby_domain = standby.get("failure_domain")
    independent_ingress = require(
        isinstance(primary_domain, str) and bool(primary_domain.strip())
        and isinstance(standby_domain, str) and bool(standby_domain.strip())
        and primary_domain != standby_domain,
        "independent_ingress_failure_domains_unverified")

    for node_name, node in (("primary", primary), ("standby", standby)):
        for check in CHECKS:
            require(_passed(node, check), f"{node_name}_{check}_not_pass")
        for vantage in VANTAGES:
            require(_passed(node.get("client_vantages"), vantage),
                    f"{node_name}_{vantage}_client_path_unverified")
    dns_endpoints = [
        node.get("dns_endpoint") for node in (primary, standby)
    ]
    proxy_endpoints = [
        node.get("proxy_endpoint") for node in (primary, standby)
    ]
    dns_distinct = require(
        all(isinstance(x, str) and x.strip() for x in dns_endpoints)
        and dns_endpoints[0] != dns_endpoints[1],
        "independent_dns_endpoints_unverified")
    proxy_distinct = require(
        all(isinstance(x, str) and x.strip() for x in proxy_endpoints)
        and proxy_endpoints[0] != proxy_endpoints[1],
        "independent_proxy_endpoints_unverified")
    require(_passed(client, "dns_fallback_configured_and_tested"),
            "client_dns_fallback_unverified")
    require(_passed(drills, "dns_outage"), "dns_outage_drill_unverified")
    require(_passed(drills, "rollback"), "rollback_drill_unverified")

    primary_services = primary.get("services") if isinstance(primary.get("services"), dict) else {}
    standby_services = standby.get("services") if isinstance(standby.get("services"), dict) else {}
    proxy_service_healthy = True
    egress_unchanged = True
    latency_ok = True
    for service in PROXIED:
        p = primary_services.get(service) if isinstance(primary_services.get(service), dict) else {}
        s = standby_services.get(service) if isinstance(standby_services.get(service), dict) else {}
        for label, observation in (("primary", p), ("standby", s)):
            if not all(_passed(observation, name) for name in ("dns", "tls", "app")):
                reasons.append(f"{label}_{service}_end_to_end_unverified")
                proxy_service_healthy = False
        ips = [p.get("egress_ipv4"), s.get("egress_ipv4")]
        if not (all(_valid_public_ipv4(ip) for ip in ips) and ips[0] == ips[1]):
            reasons.append(f"{service}_stable_egress_unverified")
            egress_unchanged = False
        p95, standby_p95 = _ms(p.get("p95_ms")), _ms(s.get("p95_ms"))
        if p95 is None or standby_p95 is None or standby_p95 > p95 * max_latency_ratio or standby_p95 - p95 > max_extra_ms:
            reasons.append(f"{service}_latency_budget_unverified")
            latency_ok = False

    common = (
        independent_ingress and dns_distinct and proxy_distinct
        and all(_passed(node, check) for node in (primary, standby) for check in CHECKS)
        and all(_passed(node.get("client_vantages"), vantage)
                for node in (primary, standby) for vantage in VANTAGES)
        and _passed(drills, "rollback")
    )
    dns_ready = common and _passed(client, "dns_fallback_configured_and_tested") and _passed(drills, "dns_outage") and proxy_service_healthy and egress_unchanged and latency_ok

    # Identical egress IP alone could mean a shared single point of failure.
    # Separate egress failure domains + proven movable/stable exit are mandatory.
    egress_domains = (primary.get("egress_failure_domain"),
                      standby.get("egress_failure_domain"))
    independent_egress = require(
        all(isinstance(d, str) and bool(d.strip()) for d in egress_domains)
        and egress_domains[0] != egress_domains[1],
        "independent_egress_failure_domains_unverified")
    require(_passed(drills, "proxy_outage"), "proxy_outage_drill_unverified")
    require(_passed(client, "proxy_fallback_configured_and_tested"),
            "client_proxy_fallback_unverified")
    require(_passed(drills, "stable_exit_after_proxy_outage"),
            "exit_continuity_drill_unverified")

    proxy_ready = (
        dns_ready and independent_egress
        and _passed(drills, "proxy_outage")
        and _passed(client, "proxy_fallback_configured_and_tested")
        and _passed(drills, "stable_exit_after_proxy_outage")
    )
    return {
        "schema_version": 1,
        "assessment_kind": "offline_supplied_evidence_not_live_verification",
        "dns_failover_candidate": bool(dns_ready),
        "proxy_failover_candidate": bool(proxy_ready),
        "stable_egress_candidate": bool(egress_unchanged and independent_egress),
        "latency_budget_candidate": bool(latency_ok),
        "production_switch_enabled": False,
        "reasons": sorted(set(reasons)),
        "checked_proxied_service_count": len(PROXIED),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = assess(json.loads(args.evidence.read_text(encoding="utf-8")))
    payload = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
