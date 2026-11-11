# Code review — v23 RU first hop through private WireGuard, 2026-11-11

Status: **PREVIEW ONLY — NOT APPROVED FOR LIVE PHONES**. Reviewed branch:
`fix/meta-routing-quic-sni-validation`, draft PR #87. No production deployment was
performed during this review.

## Verified baseline

- Last 30-minute v16 trial: [Actions #43047967491](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43047967491).
  `iglite_sni_syn=7813`, `iglite_sni_target_clienthello=0`,
  `iglite_sni_sni_split=0`. This does **not** prove that an Instagram TLS
  ClientHello reached the server or that an Android browser can use Instagram.
- Trial and nft teardown verified in that run, and independent restoration
  verified in [Actions #43053631549](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43053631549).
- RU -> DE **public IPv4:443** with SNI `i.instagram.com` timed out; RU ->
  `10.66.77.1:443` over WireGuard completed the TLS exchange but failed
  hostname verification when Meta SNI routing was absent. [Actions
  #43054783506](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43054783506).
- The prototype only renders candidates in memory:
  `scripts/meta_v23_ru_firsthop_preview.py`. No two-server orchestrator
  deploys/reverts them, and the v15 live launcher remains intentionally
  quarantined.

## Issues fixed in the code during this review

1. **P1 — Unverified origin IPs.** v23 accepted any publicly routable IP as
   an origin even when no valid certificate for that exact hostname was
   checked. Added `verify_pinned_origin_ip(host, ip)` to owner renderer and
   required a successful hostname-verifying TLS check for every v23 origin.
   Offline fixtures inject a verifier explicitly; a real render defaults to
   real TLS checking.
2. **P1 — Wrong target for non-Meta HTTPS.** Fixed RU candidate to route only
   exact allowlisted SNI to `10.66.77.1:443`, while other SNI connects to
   the existing RU `188.120.254.223:443` local listener. Backend selection is
   now a separate testable function. This does **not** remove the initial
   8-byte window effect on non-Meta HTTPS connections from the selected NAT IP.
3. **P1 — The observer silently listened to DE instead of RU.** Added explicit
   RU `188.120.254.223`/ `ens3` or DE `89.125.90.101` / `eth0`
   pre-DNAT capture configuration and input validation.
4. **P2 — Unbounded or invalid peer/duration configuration.** v23 requires a
   distinct globally routable test IPv4 and includes a 900/1800-second worker
   lifetime mapping. This is a worker bound, **not** a production rollback timer.
5. **P1 — Inconsistent domain coverage.** Offline tests now assert parity
   between the DNS route allowlist and the TCP SNI allowlist.

## Remaining blockers

- **P0 — Global DNS**: `core_add(... route_edge=RU_EDGE)` inserts owner templates
  into the shared Corefile, without restricting the DNS response to one client.
  Other SmartDNS users may get the RU A answer without access to the
  corresponding experimental TCP path. A validated per-client `view` (or
  equivalently isolated DNS listener) is required. The official
  [CoreDNS view documentation](https://coredns.io/plugins/view/) describes
  `incidr(client_ip(), ...)`, ordered filtered server blocks, and catch-all
  fallback; deployment additionally requires verifying this specific binary,
  its Corefile syntax, and preservation of real client source IP. **Do not
  assume the current installation has a usable view plugin.**
- **P0 — Shared RU HTTPS interception**: the nft rule still matches one
  source IP and *all* destinations to RU public TCP/443. It cannot know the
  hostname before ClientHello. Non-Meta is now forwarded to RU, but the
  small TCP receive window is still initially applied to those connections.
  Preventing all cross-service effects requires a separate ingress IP or a
  different, isolated interception design.
- **P0 — No atomic two-server deployment and rollback**: v23 has no
  production-ready timed plan which installs DE SNI routing and RU receiver,
  switches source-scoped DNS last, and independently rolls back each server.
  It must also recover correctly after partial failure or process death.
- **P0 — No verified external Android handshake**: no RU packet capture, real
  Android TLS ClientHello, and verified Instagram response through the full
  phone -> RU -> WG -> DE -> origin path have been observed.
- **P1 — RU existing port 443**: previous read-only checks confirm a listener
  exists, but do not verify that connecting from RU to its own public IP:443
  preserves the original non-Meta application behavior. Test this before use.
- **P1 — QUIC/IPv6 and client resolver fallbacks**: v23 handles only
  IPv4/TCP; no browser/application end-to-end outcome is guaranteed. DNS
  A/AAAA/HTTPS/SVCB/CNAME answers and Android DNS caches need real checks.
- **P1 — No exact real-device association**: source NAT IPv4 alone cannot
  identify an Android device; correlate with a bounded client-side test
  timestamp or explicit PCAP before claiming a split worked.

## Evidence / CI

The reviewed code/tests are in [PR #87](https://github.com/grunvald91/telegram-proxy-infra/pull/87).
Before this review, v23 had five textual/offline cases and no pinned TLS check.
After correction [v23 Actions #43057521277](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43057521277)
reported eight v23 tests plus five isolation-quarantine tests passing.
The corresponding build exercises deterministic renders, fallback selection,
observer filter creation and guardrails. It does **not** execute a complete
WireGuard/Instagram client path.

Decision: **do not merge as a functional Instagram unblocker**. The
preflight code is improved, but critical live routing/rollback and source
isolation remain incomplete. No changes were applied to working DNS/VPN/MTProxy
during the v23 review.
