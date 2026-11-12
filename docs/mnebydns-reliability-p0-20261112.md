# MNEBYDNS reliability — P0, 12 November 2026

Status: implementation proposed in isolated PR. No production routes, VPN, proxy or billing services are changed.

## Four customer outcomes and the safe delivery order

1. Stable per-service egress: the current single foreign node gives one candidate public exit for proxied traffic. First measure the actual node outbound IP and the DNS ingress route; these checks alone **do not prove** every service, app, or client reaches the target with that IP. Do not silently change countries when failing over.
2. DNS and proxy redundancy: test resolver failures independently of proxy failures and always check an ordinary direct domain. A second upstream resolver on the same VPS is not independent DNS ingress HA. No failover is enabled in this P0 phase.
3. Automatic supported-service checks: use the pre-existing four scheduled monitoring runs per day. Distinguish DNS mapping, IPv6 bypass risk, TLS passthrough, and eventually application HTTP status / real phone functionality. A TLS handshake does not prove Instagram login or that 403/451 has disappeared.
4. Simple first launch: later add individual DoT/DoH onboarding, platform-appropriate setup and activation diagnostic. Do not sell byte-metered DNS-only connections until the user-to-flow identity has been confirmed.

## This PR implements

- Replace the historical scheduled public DoT checker *in the same workflow and same cadence*; it now uses its own versioned, tested Python parser and does not fetch an old cross-repository commit.
- Explicit service registry with established expected proxy DNS routes for Gemini, Claude, Grok, X and TikTok. Instagram, Threads and Microsoft remain **observe-only**, not asserted to work. Ordinary websites and Telegram are direct-only controls.
- DNS-over-TLS verified by resolver TLS hostname and DNS response transaction/question. Compare exact A answers against the expected ingress IP. Query AAAA separately to flag possible IPv6 bypass without claiming a verified device leak.
- Check certificate-verified TLS handshakes using real SNI *only for domains DNS actually maps to the ingress*. This records transport evidence but is not yet a strict application-availability gate.
- Pin the existing SSH host key, query the foreign node's direct public IPv4 egress through HTTPS and compare it with the expected IP; never print the detected IP in logs. Unknown measurement is reported as unknown, not a fabricated pass.
- Report JSON status without subscriber identity, tokens, traffic data or raw public IP address; retain the artifact for 7 days. Route regressions and confirmed egress mismatch cause a failed workflow.
- Unit tests run for every PR touching these files. PR tests do not receive the SSH password. Production route mutation / auto-restart / failover is absent.

## Guardrails

No edits to CoreDNS, nginx, Xray, WireGuard, MTProxy, firewall, OS, TLS keys, DNS rewrites, paid product access or live egress. No new cron frequency or new Actions workflow. Monitor is only an external GitHub runner vantage; it is not an Android/iPhone/ISP end-to-end test.

## Gates before P1

| Gate | Required external evidence | Status |
|---|---|---|
| P0-A | CI tests pass; read-only scheduled monitor runs successfully from main | UNVERIFIED until measured |
| P0-B | Real Android and iPhone checks on Wi-Fi and cellular; p50/p95 baseline and no ordinary-web regression | UNVERIFIED |
| P0-C | Correlated egress IP per service and actual traffic path, not only node direct IP | UNVERIFIED |
| P0-D | Isolated DNS upstream vs full ingress vs proxy-outage tests; ordinary sites unaffected | UNVERIFIED |
| P0-E | Independent failure domain, encrypted backups, restore test, bounded rollback and authorization | UNVERIFIED |

## P1 after gates

Prepare an independent DNS ingress; prove failover from user-side networks without changing ordinary browsing. Keep the same foreign exit IP when possible, or explicitly avoid promising IP continuity until a proven floating-egress mechanism exists. Next implement bounded proxy recovery policies with cooldown and rollback, and only then publish frictionless personal onboarding. Existing production state remains unchanged throughout this PR.


## Initial read-only run and review fix (12 November 2026)

The first merged workflow returned zero **DNS / direct-egress** regressions, but nine TLS SNI passthrough attempts timed out from the public GitHub runner. This must **not** be presented to customers as nine working services: a correct DNS answer does not establish a working TCP/443 connection. Instagram and Threads remained direct-mode DNS observations, not confirmed functional applications.

The next monitor revision separately tests raw ingress TCP/443 and a control TCP/443 connection to an ordinary public site. It does not guess whether failures are caused by the exit server, access network, filtering, or origin policy. If the control host is reachable but ingress TCP is not, the GitHub Action fails as a **target-specific external path alarm**, not as proof that every phone/ISP is affected. When ingress TCP is unavailable, per-service TLS probes are skipped rather than repeatedly timing out and incorrectly marking individual applications as failed. Per-service application-level tests and independent client vantages remain required.
