# MNEBYDNS Instagram/Threads — causal root-cause test plan, 2026-11-09

## Status and safety

**Prepared, NOT deployed.** No changes to `main` or the stable six-service DNS/Nginx/Xray installations. This branch contains:
- isolated Meta-only guarded 28-minute deployment workflow (arming requires **explicit** commit to `ops/mnebydns-meta-rootcause-arm.txt`, which is deliberately not created now);
- independent DE/RU snapshot preflight and a real QUIC v1 reference;
- read-only in-memory TCP/UDP interface stage observers (no PCAP file, IP, SNI, raw packet or payload journalled);
- extra UDP socket MTU errors, upstream response counters, two-stage synthetic round-trip regression;
- read-only per-run aggregate report workflow (arming via `ops/mnebydns-meta-rootcause-report.trigger` with a numeric run ID);
- two separate systemd watchdog rollback timers and independent observer lifetime limit.

Preflight: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42608571122 .
Offline CI: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42610416269 .
Live-independent real QUIC-to-Meta reference (five verified TLS handshakes): https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42610576245 .

## Evidence and unresolved cause

- The first Android PCAP showed mostly direct-to-Meta TLS connections and QUIC Initials.
- The second Android PCAP (before the QUIC relay) showed 107 Meta TCP ClientHello flows reaching RU and 85 outbound QUIC v1 Initial packets destined to RU; no incoming QUIC response was seen in that capture.
- The packet observer was tested locally on the second owner capture and correctly counted 107 Meta ClientHello and 85 incoming QUIC v1 packets *from the perspective of the owner device*. This is **not** a post-QUIC-deployment phone capture.
- The DE server can independently verify valid TLS certificates for i.instagram.com, i-fallback.instagram.com, iglite-z.instagram.com, test-gateway.instagram.com, graph.instagram.com, threads.com and graph.facebook.com (7/7).
- Five direct QUIC v1 handshakes from disposable GitHub runner to Meta passed, with certificate verification.
- Previous test runs only saw synthetic QUIC admissions on both servers; no evidence of real mobile QUIC admissions. SNI-based carrier blocking is therefore a hypothesis, not an established root cause.

## Mandatory *pre-phone* gates in new canary

1. Validate staged scripts, rollback scripts, DNS renderer, packet observers and Nginx configuration. Refuse unexpected stable checkpoint differences.
2. Test 13 Meta hostnames RU→private DE TCP with verified TLS; test same 13 on RU localhost. These tests alone are **not** a public ingress proof.
3. Start both independent passive interface observers, require pcap-readiness markers (RU public ens3, DE WG tg-relay). Each observer exits before guarded expiry.
4. Connect from DE to RU **public 188:443**, verifying 4 real Meta TLS certificates. On any failure, **abort and rollback without activating phone DNS**.
5. Stage isolated RU public UDP/443 → DE private UDP/19444 through WireGuard. Confirm synthetic admission only, never call it full QUIC success.
6. From the same disposable GitHub runner, compare certificate-verified genuine QUIC v1 handshakes directly to Meta versus via RU:443 for i.instagram.com, i-fallback.instagram.com, test-gateway.instagram.com, threads.com, graph.instagram.com. Abort if a direct-verified reference fails through RU; require at least three verified reference targets. Runner observations do NOT prove mobile operator behavior.
7. After all synthetic/runner tests, record `PRE_PHONE_` baseline cumulative counters for TCP/UDP ingress and QUIC relay, then activate Meta-only DNS.
8. Verify 13 synthetic Meta A answers, six previously working A answers, expected Meta AAAA/HTTPS/SVCB no-data responses, stable DNS untouched, both watchdog rollback timers armed.
9. Only then announce an exact expiry to the owner.

## One simple actual phone test

With ordinary VPN off and system Private DNS set to MNEBYDNS, owner opens Instagram for about 60 seconds, then Threads for about 60 seconds. Owner only reports whether login/feed/images load, and the rough start time. **No PCAPdroid or repeated captures requested.** Read the staged report while the guarded window is still open or after automatic rollback (journald persists).

## Diagnostic decision matrix (compare counters to PRE_PHONE baseline)

| Observed difference from baseline | Conclusion supported |
|---|---|
| DNS checks fail | Our DNS overlay or external DNS path is broken; do not blame SNI |
| DE direct Meta cert checks fail | Meta origin/outbound/resolution from DE is broken |
| RU-local succeeds but DE→RU-public TLS fails | Public RU ingress or DE→RU network path is broken; stop before phone test |
| Direct QUIC real handshake succeeds but via RU fails | QUIC relay/return path or reachability through RU needs fixing; stop before phone test |
| Phone reports attempts but RU public tcp SYN/udp RX do not increase | Could be operator/network drop, client DNS bypass or no actual connection attempt; SNI not proved |
| RU sees TCP SYN+ClientHello but DE WG TCP packets do not rise | RU SNI route/Nginx/intermediate TCP forwarding problem |
| RU and DE see TCP; DE Meta Nginx status=502 or origin reply bytes=0 | Upstream DNS/routing/backend issue; fix servers |
| DE receives Meta TCP response but RU interface never sends it | DE→RU WireGuard/TCP response forwarding; fix servers |
| RU UDP RX increases but parser rejected/overflow/emsgsize rises | QUIC parser, flow limits, MTU or routing defect; fix servers |
| DE QUIC receives public origin UDP replies but RU upstream reply RX stays flat | Private WireGuard UDP response path defect |
| RU sends TCP/UDP responses, but application still fails | Client return path, TLS/session/app-layer requirements or network filtering possible; not yet proof of SNI |

Because observations are aggregates over a shared server port, another active user session could contribute to counts. Controlled short windows and the PRE_PHONE snapshot reduce but cannot eliminate this ambiguity.

## Exact SNI attribution requires one controlled client-side differential

Server-only tests cannot prove **carrier SNI filtering** when failure occurs before RU. OONI's experimental SNI-blocking specification calls for the **same client network, IP, port and TLS test-helper**, comparing a target SNI with a control SNI while retaining consistent server behavior. Differences must be repeated to avoid false positives.

- https://github.com/ooni/spec/blob/master/nettests/ts-024-sni-blocking.md
- https://github.com/ooni/spec/blob/master/techniques/tq-026-SNI-free-and-fake-SNI-TLS-ClientHello.md
- https://ooni.org/support/interpreting-ooni-data/
- https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html
- https://www.rfc-editor.org/rfc/rfc9001.html

This controlled differential is **NOT** included in the initial no-extra-app trial; its necessity will be decided only after per-hop data. A SNI hypothesis must not be called confirmed solely from lack of ServerHello.

## Acceptance

A repair is complete only after a real Android Instagram and Threads test confirms loading of both apps, with no stable-route regression and with watchdog rollback or an independently reviewed permanent promotion. Until then the Meta routes stay experimental.
