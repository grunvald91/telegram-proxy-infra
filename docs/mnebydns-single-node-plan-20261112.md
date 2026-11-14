# MNEBYDNS single-node roadmap — 12 November 2026

**Owner decision:** use only the existing foreign VPS for DNS and SmartDNS proxy for now. Do not configure the Russian server or any other VPS as DNS/proxy standby. Additional independent servers and cross-server failover are **deferred until there is stable paying-client traffic**. This file is not authorization to buy any server.

## What is verified vs unverified

- Public DoT queries for existing configured services have passed in the external read-only monitor. The monitor compares the direct **node** public IPv4 against the expected foreign IP; this is not proof of the exit IP seen by every application.
- GitHub-runner public TCP/443 transport is path-dependent; a runner timeout is not a customer outage. There is no automatic routing reaction.
- Actual phone application access, service-specific egress, single-server recovery times and paid-client activation still require validation.
- Quad9 upstream redundancy (9.9.9.9 / 149.112.112.112) is a within-node resilience feature. It **cannot** survive loss of the VPS.

## Single-node delivery milestones

1. **Synthetic per-service test from the existing VPS (this PR).** During each of the existing 4x/day read-only health runs, connect from the foreign VPS to its own 127.0.0.1:443 with real origin hostname SNI, verify the certificate, and read only the first HTTP status line. Only fixed, established proxied hostnames are checked. Microsoft is observation, not guaranteed supported routing. Don't restart or change Nginx.
2. **Stable node exit monitoring.** Continue comparing the outbound node IPv4 against the expected IP. Do not promise IP stability per app until real client or equivalent path-specific evidence exists. No automatic switch to another country/IP.
3. **Quality baseline.** Measure real service availability and latency from a phone on Wi-Fi and cellular, retaining ordinary websites and Telegram as direct controls. DNS, local TLS, HTTP status and working applications are separate evidence levels.
4. **Simple onboarding.** Test Android Private DNS hostname input and iOS/macOS install/remove profile flows with a real user activation check. A successfully installed profile alone does not prove service access. No per-user byte billing without robust client-to-flow attribution.
5. **Single-node fault recovery.** Evaluate upstream DoT fallback, service health/restart, host reboot recovery and rollback using staged canaries before any live changes. This PR does not restart any daemon.

## This release: safety and interpretation

- The new scripts/mnebydns_onnode_service_probe.py is **read-only**, bounded to at most three parallel workers (two in production), opening a small number of synthetic HTTPS requests only to the foreign VPS's local port 443. It sends no cookies, logins or credentials and reads **no response body**.
- Verified TLS is a transport observation. HTTP 200–399 is an HTTP signal. HTTP 403/404/451/429/5xx may have several causes and **does not** establish either real client success or confirmed geographic blocking. Unknown/error remains unverified.
- The existing mnebydns-stable-five-public-health.yml workflow is reused, keeping cron 17 1,7,13,19 * * *, the pinned SSH host key and one existing foreign server. Sanitized onnode-health.json joins health.json in the existing artifact, retained seven days.
- PR runs offline tests only; the remote password is unavailable there. Live synthetic checks only on the pre-existing schedule or deliberate manual invocation of that workflow.
- No server config mutation, paid VPS, backup/failover, extra scheduled workflow, route rewrites, subscriber measurement or public traffic interception.

## Next release after this milestone

Produce a service-by-service health summary that distinguishes:
- dns_mapped: the resolver returned the configured address;
- server_tls_verified: certificate-verified SNI connection at localhost:443;
- http_response_observed: an initial HTTP status line;
- client_application_verified: only after actual tests from client ISP networks.

Never call a service fully operational on DNS-only, TLS-only or status-line-only evidence. Do not enable auto failover or a different exit IP.
