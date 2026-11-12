#!/usr/bin/env python3
"""Fail-closed interpretation of read-only Meta DNS / SNI probe evidence.

This is a diagnostic classification tool, not a routing controller.
It NEVER changes DNS/Nginx/firewall and never claims Android E2E success.
"""
from __future__ import annotations

import pathlib
import re
import sys

META = {
    "i_instagram_com": "i.instagram.com",
    "iglite_z_instagram_com": "iglite-z.instagram.com",
}

def parse(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", key):
            values[key] = value
    return values

def a_de_count(value: str) -> int:
    m = re.fullmatch(r"RCODE0_A_DE([0-9]+)_A_RU[0-9]+_A_OTHER[0-9]+_AAAA[0-9]+_CNAME[0-9]+_HTTPS[0-9]+_SVCB[0-9]+", value)
    if not m:
        raise ValueError("DoT A response missing or invalid")
    return int(m.group(1))

def classify(values: dict[str, str]) -> dict[str, str]:
    required = {"external_dot_A_www_youtube_com", "no_live_file_changes"}
    for host in META:
        required.update({
            "external_dot_A_" + host,
            "external_dot_AAAA_" + host,
            "de_nginx_route_" + host + "_count",
            "de_local_ingress_" + host,
            "de_to_origin_" + host,
        })
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError("incomplete evidence: " + ",".join(missing))
    if values["no_live_file_changes"] != "true":
        raise ValueError("read-only guarantee not reported")
    outcomes: dict[str, str] = {}
    for host in META:
        dns = a_de_count(values["external_dot_A_" + host])
        route_raw = values["de_nginx_route_" + host + "_count"]
        if not route_raw.isdecimal():
            raise ValueError("invalid route count for " + host)
        route_count = int(route_raw)
        local = values["de_local_ingress_" + host]
        origin = values["de_to_origin_" + host]
        if dns == 0 and route_count == 0:
            status = "DIRECT_NOT_PROXY_ROUTED"
        elif dns == 0 and route_count > 0:
            status = "INGRESS_CONFIGURED_BUT_DNS_DIRECT"
        elif dns > 0 and route_count == 0:
            status = "UNSAFE_DNS_POINTS_AT_MISSING_INGRESS_MAP"
        elif route_count != 1:
            status = "UNSAFE_AMBIGUOUS_INGRESS_MAP"
        elif not local.startswith("verified_"):
            status = "UNSAFE_INGRESS_TLS_NOT_VERIFIED"
        elif not origin.startswith("verified_"):
            status = "UNSAFE_ORIGIN_TLS_NOT_VERIFIED"
        else:
            status = "PROXY_CANDIDATE_PHONE_E2E_UNVERIFIED"
        outcomes["meta_" + host] = status
    outcomes["youtube_dns_a_to_de"] = "yes" if a_de_count(values["external_dot_A_www_youtube_com"]) > 0 else "no"
    outcomes["android_end_to_end"] = "NOT_TESTED_BY_SERVER_PROBE"
    outcomes["routing_changes_performed"] = "none"
    return outcomes

def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: meta_v12_routing_gate.py AGGREGATED_PROBE_OUTPUT")
    data = parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    for key, value in classify(data).items():
        print(key + "=" + value, flush=True)

if __name__ == "__main__":
    main()
