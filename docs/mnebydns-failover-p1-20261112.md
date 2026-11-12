# MNEBYDNS P1 — readiness gate for independent failover

**Status (2026-11-12): preparation only. No backup ingress has been verified, no live failover enabled.**

## What is already present

- A CoreDNS migration script contains two Quad9 upstream DNS-over-TLS addresses (`9.9.9.9` and `149.112.112.112`) with sequential policy. This is upstream redundancy *inside one foreign VPS*; it is **not** independent DNS ingress HA. Production application must be verified separately (source: `scripts/mnebydns-dot-resilience-20261111.py`).
- The current public reliability monitor observes DNS answers, TCP/TLS and one direct node public egress, but does **not** establish per-service client egress or phone E2E. Source: `scripts/mnebydns_reliability_monitor.py`, `docs/mnebydns-reliability-p0-20261112.md`.

## P1 release criteria and ordering

1. **Record the current client baseline:** for each supported proxy service, get Wi-Fi and cellular client proof of DNS route, application success, actual public exit IPv4 and p95 response time. Check ordinary direct websites. Unknown observations are not success.
2. **Independent DNS ingress:** provision a separate failure domain with a distinct authenticated DoT endpoint. Validate certificates and service DNS routes. Add both resolvers to a *test* client profile. Simulate primary DNS outage and restoration; confirm ordinary sites stay usable. Do not change the production profile before the test passes.
3. **Proxy recovery:** validate a distinct proxy endpoint, independent ingress and independent egress failure domains. Re-test every supported service, preserve the same observed public exit IPv4 when promising stable IP, prove the exit-continuity drill, ordinary-web checks and rollback. If the spare uses a different IP, stability is not established; do not claim it.
4. **Quality budget (initial engineering policy, adjustable before release):** standby p95 no greater than 1.25× primary p95 **and** no more than 100 ms slower for each supported service. Use actual repeated samples from both networks; these are proposed gating limits, not measured performance or a contractual SLA.
5. **Only after measured readiness:** design a bounded manual-approval failover policy with multi-sample hysteresis, cooldown, automatic rollback and explicit client notification for any IP change. No automated switch exists in this PR.

## Offline gate implementation

`scripts/mnebydns_failover_readiness.py --evidence EVIDENCE.json`

The JSON evidence is **operator-supplied** and must be backed by timestamped genuine measurements; the checker does not collect or authenticate it. Do not put subscriber identifiers, tokens or links into the evidence. Store raw operational evidence securely outside Git. The JSON keys are:

- `schema_version: 1`
- `primary` / `standby`: each has unique `failure_domain`, `dns_endpoint`, `proxy_endpoint`, and `egress_failure_domain`, plus `dot_tls`, `proxy_tls`, `ordinary_web` as `"pass"` only after verification; `client_vantages: {cellular: "pass", wifi: "pass"}`
- `primary.services` / `standby.services`: maps each established proxied service identifier from `SERVICES` to `{dns:"pass", tls:"pass", app:"pass", egress_ipv4:"<observed public IPv4>", p95_ms:<measured number>}`
- `client`: `dns_fallback_configured_and_tested`, `proxy_fallback_configured_and_tested` (status `"pass"` only after real testing)
- `drills`: `dns_outage`, `proxy_outage`, `rollback`, `stable_exit_after_proxy_outage`

Missing fields / `"unknown"` / evidence of different exit IP / latency regression **block** the candidate. The exit IPs are compared internally, not printed. DNS failover readiness is separate from proxy readiness: a DNS backup using the same underlying exit can pass the *DNS* gate but cannot claim full proxy HA. The checker always sets `production_switch_enabled=false`; even a fully populated test fixture is never permission to change traffic.

`python3 -m unittest discover -s scripts/tests -p 'test_mnebydns_failover_readiness.py' -v`

## Limitations / next real work

- No new spare VPS was purchased or configured.
- No actual primary failure was induced.
- No client path, mobile connectivity, per-service public exit, SLA or recovery time has been measured by this offline tool.
- Next milestone: select or identify an independent spare ingress, collect signed/traceable observations, run a *test-client-only* fault drill, and populate the gate. Keep the current customer configuration untouched until verified.
