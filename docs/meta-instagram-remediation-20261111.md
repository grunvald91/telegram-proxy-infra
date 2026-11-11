# Instagram / Instagram Lite: remediation and evidence — 11 Nov 2026

**Scope:** MNEBYDNS RU ingress 188.120.254.223, DE edge 89.125.90.101, Android Instagram and Instagram Lite. This document records evidence from already completed runs and a safe, incremental repair sequence. It does not authorize or imply deployment.

## Source of truth

- **Active server infrastructure**, including the historical read-only SSH inventory and v11 rollout scripts: [telegram-proxy-infra](https://github.com/grunvald91/telegram-proxy-infra).
- **Observed v11 route-only experiment (14:48:44–15:04:09 MSK 11 Nov):** [Actions run 43015018176](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43015018176). GitHub result `success` means that the diagnostic and restoration workflow passed; it is **not** an Instagram app success result.
- **Read-only RU and DE inventory / path comparison:** [Actions run 43016301879](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43016301879). Historical snapshot, not proof of current server state.
- **Public DoT A/AAAA classification after rollback:** [Actions run 43017666389](https://github.com/grunvald91/Mnebyvpn/actions/runs/43017666389). Probe originated from GitHub infrastructure, not the Russian mobile ISP.
- **Prior Android PCAPdroid report (9 Nov):** original offline report `REPORT.md` and the user's captures. The report counted 107 TCP connection attempts to RU:443, 2 TCP flows with reply payload, 85 QUIC Initial messages to RU:443 and 0 observed inbound UDP payload replies. These are **capture-specific**, not a current network measurement. The original PCAP bytes are not included in this GitHub branch.

## What happened in v11

1. The v11 script [mnebydns_iglite_route_only_v11.py](../scripts/mnebydns_iglite_route_only_v11.py) temporarily added 11 **exact** Meta DNS and Nginx SNI routes on DE, checked DoT answer types, observed inbound TCP SNI, and restored original configurations. The run reported `iglite_v11_rollback=VERIFIED_CONFIGS_AND_SERVICES_NO_TCP_WRITES`.
2. v11 did **not** rewrite TCP packets, change kernel window scaling, change nftables, or fragment TLS ClientHello. A packet observer measured TCP segment boundaries; it is **not an SNI splitting implementation**.
3. The run logged `iglite_sni_target_clienthello=6`, `iglite_sni_sni_split=0`, `iglite_sni_sni_unsplit=6`, `iglite_sni_other_sni=63`. Among complete target handshakes, `graph.facebook.com=2` and `z-m-gateway.facebook.com=4`; listed `iglite-z.instagram.com` and `i.instagram.com` each had 0 complete handshakes. The observer explicitly printed `iglite_sni_android_identified=false`: no attribution of these flows to the two phones is justified.
4. The prior v10 variant changed global TCP receive window properties for non-Meta TCP as well; it must **not** be reintroduced for a Meta-only fix, given concurrent reports of YouTube failures.
5. The later RU read-only path comparison reported TLS 1.3 to `i.instagram.com` through DE's **WireGuard address** `10.66.77.1:443` (~406 ms) but a timeout through DE's **public address** `89.125.90.101:443` (~5119 ms), both probed from RU. This narrows the fault to endpoint/path-dependent behavior; it **does not** establish which Russian-network middlebox, if any, caused the failure.
6. The post-trial public DoT probe reported that Instagram A addresses were no longer DE/RU ingress addresses and AAAA answers existed; YouTube A still routed to DE. This is compatible with the expected temporary v11 rollback. Restoring direct Meta routing is **not itself an Instagram fix**.

## Code issues fixed on this branch

- **P1 — truncated PCAP header accepted as clean EOF:** the observer formerly caught `EOFError` reading *any* part of a 16-byte record header and silently ended parsing. It now distinguishes clean EOF at a record boundary from a truncated record and fails closed.
- **P1 — ambiguous SNI TCP segmentation with snaplen truncation:** the observer previously treated `wire_len` as the observed segment-end even when captured TCP bytes were shorter. It now records `sni_boundary_indeterminate` rather than asserting split/unsplit when a segment was not fully captured.
- Offline tests cover both defects, normal complete PCAPs, and existing exact-host safety contracts. All changes are to analysis tooling; no DNS server, ingress routing, packet manipulation, or production state is altered.

## Remediation gates

| Gate | Required verification | Status as of this document |
| --- | --- | --- |
| P0: server baseline | Fresh read-only RU/DE inventory, ingress listeners, current config SHA, WireGuard health, Meta routing & rollback marker state | Historical read-only snapshot available; **fresh state unverified** |
| P0: client-to-edge path | Concurrent Android PCAP plus RU and DE *aggregated*, per-direction TCP and UDP counters with time correlation | Prior Android PCAP and DE capture are **not a matched pair** |
| P1: public vs private DE ingress | Separate controlled TLS probes from RU to public DE and WG DE, with exact SNI and no global DNS change | **Difference observed; cause unverified** |
| P1: exact DNS route | Validate A, AAAA, HTTPS, SVCB, CNAME for each *proven* host; ensure no unintended IPv6/direct fallback; keep YouTube controls intact | v11 pilot passed temporary DNS checks; not live now |
| P1: TCP TLS passthrough | Prove RU ingress → DE ingress → origin → DE → RU → Android with end-to-end TLS validation and response bytes | **Not verified** |
| P1: QUIC UDP/443 | Verify listener, SNI parser compatibility, upstream TX/RX, reply forwarding, PMTU/EMSGSIZE on both nodes, v1/v2/version negotiation, with strict allowlist | Previous PCAP had 0 UDP replies; **not verified** |
| P1: SNI splitting feasibility | Show **where** ClientHello is modified **before** the filtering hop and prove segment boundary there. Server-side changes after that hop cannot fix it. | **No client-side SNI splitting implementation** |
| P2: safe CI & rollout | Offline tests, no deployment by PR, isolated canary, service regressions for YouTube/Telegram/VPN/DoT, proof of restoration | Offline CI introduced; live E2E blocked pending above gates |

### Next controlled diagnostic

Start with read-only, synchronized counters on RU and DE and a short Android session: record one exact timestamp, network (Wi-Fi vs cellular) and whether system Private DNS is enabled; avoid logging users' request bodies or credentials. Compare public DE and WG DE ingress separately and **never assume success from SYN/SYN-ACK alone**. QUIC Initial TX is not evidence of origin response. Do not turn on broad `*.instagram.com` routing or globally modify TCP sysctls or NFQUEUE rules.

The product goal is **Smart DNS without app installation**. That architecture provides control over DNS answers and servers, **not** direct control of packets leaving the phone before the first middlebox. Confirm feasibility before announcing any SNI splitting bypass.

### Test changes

- `scripts/mnebydns_iglite_sni_observer.py`
- `scripts/tests/test_mnebydns_iglite_sni_observer.py`
- `.github/workflows/mnebydns-meta-sni-offline-safety.yml`

No production test has been triggered by these changes.
