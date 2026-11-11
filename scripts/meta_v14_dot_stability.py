#!/usr/bin/env python3
"""Bounded, read-only paired DNS-over-TLS stability experiment.

Compare the public DE MNEBYDNS resolver with its known Quad9 upstream from
a GitHub-hosted runner. Never prints personal data or raw DNS payload.
This is NOT an ISP/Android test. No live configuration writes.
"""
from __future__ import annotations
from collections import Counter
import re
import sys
import time
from meta_v12_ru_de_readonly import dot_query, DE_PUBLIC, DOT_HOST

ENDPOINTS = (
    ("edge", DE_PUBLIC, DOT_HOST),
    ("quad9", "9.9.9.9", "dns.quad9.net"),
)
DOMAINS = (
    "i.instagram.com",
    "iglite-z.instagram.com",
    "www.youtube.com",
)
RR = (("A", 1), ("AAAA", 28), ("HTTPS", 65))
ROUNDS = 5
DELAY_S = 0.08

def status(result: str) -> str:
    match = re.match(r"^RCODE([0-9]+)_", result)
    if match:
        return "RCODE_" + match.group(1)
    if re.fullmatch(r"[A-Za-z]+(?:Error|Exception)", result):
        return result
    return "BAD_RESPONSE"

def sample(domain: str, typ: int, target: str, tls_hostname: str) -> str:
    try:
        return status(dot_query(domain, typ, target=target, tls_hostname=tls_hostname))
    except Exception as exc:
        return type(exc).__name__

def run() -> int:
    counters = {}
    for endpoint, target, tls_hostname in ENDPOINTS:
        for domain in DOMAINS:
            for label, rrtype in RR:
                counters[(endpoint, domain, label)] = Counter()
    for round_num in range(ROUNDS):
        for endpoint, target, tls_hostname in ENDPOINTS:
            for domain in DOMAINS:
                for label, rrtype in RR:
                    result = sample(domain, rrtype, target, tls_hostname)
                    counters[(endpoint, domain, label)][result] += 1
                    time.sleep(DELAY_S)
        print("dns_stability_round_" + str(round_num + 1) + "=finished", flush=True)
    failures = []
    for (endpoint, domain, label), counts in sorted(counters.items()):
        prefix = endpoint + "_" + re.sub(r"[^a-z0-9]", "_", domain) + "_" + label
        ok = counts["RCODE_0"]
        transient = ROUNDS - ok
        result = ("STABLE" if transient == 0 else
                  "INTERMITTENT" if transient == 1 else "REPEATED_FAILURE")
        print("dns_v14_" + prefix + "=" + result + "_NOERROR" + str(ok)
              + "_OTHER" + str(transient), flush=True)
        for code, number in sorted(counts.items()):
            if code != "RCODE_0":
                print("dns_v14_error_" + prefix + "_" + code + "=" + str(number),
                      flush=True)
        if transient >= 2:
            failures.append(prefix)
    print("dns_v14_origin=GITHUB_RUNNER_NOT_RU_ANDROID", flush=True)
    print("dns_v14_live_config_mutations=none", flush=True)
    print("dns_v14_repeated_failure_count=" + str(len(failures)), flush=True)
    return 1 if failures else 0

if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("no CLI arguments")
    raise SystemExit(run())
