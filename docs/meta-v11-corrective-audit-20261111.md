# MNEBYDNS Meta / Instagram Lite: corrective audit and next-stage gates (11 Nov 2026)

## Scope and evidence
This document records verifiable observations and **does not authorize a deployment**. The source branch is `audit/mnebydns-instagram-lite-20261111`; the corrective branch is `fix/meta-routing-quic-sni-validation`. No runtime changes are made by the corrective branch.

Primary evidence:
- [v11 Meta route-only 15-minute canary, run 43015018176](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43015018176) — the `canary` job accessed the DE server and executed the experiment, then verified restoration.
- [Joint RU/DE read-only network and service inspection, run 43016301879](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43016301879) — verified running services and compared public DE TCP/443 with private WireGuard reachability.
- [External DNS answer classification, run 43017666389](https://github.com/grunvald91/Mnebyvpn/actions/runs/43017666389) — observations from GitHub runner, **not** from an Android device in Russia.
- [Read-only diagnostics PR #82](https://github.com/grunvald91/Mnebyvpn/pull/82) — distinct from the server infrastructure and from a working SNI-splitting implementation.
- The [PCAPdroid analysis supplied in the project](https://github.com/grunvald91/Mnebyvpn/pull/82) reports 107 TCP SYN/SYN-ACK, 2 TCP streams with TLS reply data, and 85 QUIC v1 Initial without UDP replies in the 09 Nov capture. The raw PCAP was not reprocessed in this corrective branch.

## Confirmed
1. v11 explicitly declared `ROUTE_ONLY_NO_SYSCTL_NO_NFT` and temporarily routed **11 exact Meta hostnames**. The server-side observer reported `iglite_sni_target_clienthello=6`, `iglite_sni_sni_split=0`, `iglite_sni_sni_unsplit=6`. It also reported `payload_without_syn=1410`, `clienthello_record_incomplete=259`, and `android_identified=false`. These aggregate samples do **not** prove behavior of all Android packets, nor an effective client-to-server SNI fragment.
2. v11 reported `iglite_v11_rollback=VERIFIED_CONFIGS_AND_SERVICES_NO_TCP_WRITES`. This is a runner-observed verification for that test, not a claim of universal future recovery.
3. In the read-only joint check, RU-to-DE **public** TCP/443 with SNI `i.instagram.com` timed out, whereas RU-to-DE **private WireGuard** `10.66.77.1:443` completed TLSv1.3 with SNI `i.instagram.com` in about 406 ms. This is a strong reason to examine path-dependent routing, not proof of a TSPU rule or DPI mechanism.
4. The same joint check reported RU/DE WireGuard handshake, active Nginx on both nodes, DE DoT active, and `nginx -t` successful. Its DE checkpoint comparison detected DNS and Nginx changes relative to an earlier stable snapshot, while DE pilot matched. That comparison by itself does not distinguish approved additions from configuration defects.
5. The subsequent GitHub-hosted DoT check resolved Instagram names without the RU or DE ingress IPv4, while YouTube A records mapped to DE. This **post-experiment** runner result does not describe what each phone resolved during the v11 window.

## Corrective code in this branch
- `scripts/mnebydns_iglite_sni_observer.py`: distinguish clean EOF on the PCAP record boundary from a truncated 1–15-byte record header; a partial header must raise, rather than silently count as a complete capture.
- The observer flags `sni_boundary_indeterminate` if capture truncation prevents trustworthy TCP segment-boundary evidence. Such flows are not forced into `sni_split` or `sni_unsplit`.
- `scripts/tests/test_mnebydns_iglite_sni_observer.py`: synthetic tests for those cases; no PCAP or phone IPs written.
- `.github/workflows/meta-v11-observer-offline-verify.yml`: compile and run isolated regression tests on GitHub runners with no production credentials and no server writes.

## Open blockers / priority
| Priority | Blocker | Proof required |
| --- | --- | --- |
| P0 | Exact Android-to-RU (or Android-to-DE) TCP/UDP path during a user test | Time-correlated client capture and **read-only** server-side aggregate counters with baseline, plus interface and IP family. Do not infer from a GitHub runner. |
| P0 | Server-side observation cannot manipulate an earlier ClientHello crossing an upstream filtering hop | Explicit client-side packet evidence if the objective is actually to split SNI **before** that hop. A DNS-only user configuration does not implement client-side packet segmentation. |
| P1 | Public DE/443 route for `i.instagram.com` differs from WireGuard DE/443 | Compare allowlisted SNI mapping, DE public ingress listener, local vs public egress, routing and firewall counters read-only; verify with TLS certificate validation. |
| P1 | Instagram DNS answer state and IPv6/HTTPS/SVCB behavior differ from YouTube | Check exact A/AAAA/HTTPS/SVCB/CNAME per required hostname on the device; distinguish stable fail-open/direct policy from a deliberate test route. |
| P1 | QUIC/UDP request/response path is unproven | Compare client UDP sent, RU receive, RU→DE, DE→origin, and return counters; isolate MTU/EMSGSIZE and QUIC version without globally changing UDP/443. |
| P2 | SNI observer lacks complete TLS-record-fragment and offload visibility | Add offline fixtures and explicitly mark unsupported fragmented, ECH and QUIC cases as `unclassified`; never infer phone identity from server source IP. |
| P2 | Potential non-Meta regressions | Always recheck YouTube, five existing DNS routes, Telegram proxy and VPN. No global TCP window scaling or broad nft updates. |

## Go/no-go
- **GO** for further offline parser validation and read-only RU/DE diagnostics.
- **NO-GO** for production DNS cutover, SNI segmentation claims, paid-service promises, or switching global TCP/UDP policy without a device-correlated positive result.
- This branch does **not** include a client-side SNI fragmentation implementation or any claim of success bypassing TSPU.

## Follow-up real read-only verification, 13:11–13:18 UTC
- [Certificate and active Nginx SNI-map diagnostics, run 43026858488](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43026858488): after correcting the map-parser regex, RU and DE both had **zero exact SNI map entries** for `i.instagram.com` and `iglite-z.instagram.com`. DE local Nginx for either hostname failed TLS verification with **error 62 (hostname mismatch)**, while DE direct-to-Meta TLS verified. The earlier `map_count=0` measurement from a faulty regex must **not** be used.
- [Read-only route classification, run 43027791142](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43027791142): both exact Meta domains were independently classified as `DIRECT_NOT_PROXY_ROUTED`; YouTube A still mapped to DE; `android_end_to_end=NOT_TESTED_BY_SERVER_PROBE`.
- [WireGuard / public DE probe, run 43026158386](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43026158386): both WG MTUs are 1360; no RU/DE UDP/443 listener was found via `ss -lun`; RU to DE's public 443 times out for Meta SNI but not for `claude.ai`. These **server-origin** measurements do not isolate mobile TSPU behavior.
- [Offline route-state classifier](../scripts/meta_v12_routing_gate.py) now fails closed for missing/incomplete probe evidence, a DNS override pointing to a missing ingress SNI map, or an unverified ingress TLS certificate. For a direct/no-route state it reports `DIRECT_NOT_PROXY_ROUTED` and never claims bypass success. See [synthetic tests](../scripts/tests/test_meta_v12_routing_gate.py).
- The mismatch occurred after the temporary Meta experiment rolled back, and is therefore **not independently evidence of Nginx corruption**. Current SmartDNS policy sends these tested Meta domains directly; merely fixing PCAP/SNI observer parsing does not make Instagram work.
- **Next safe engineering gate:** compare a separately staged exact-host Meta route against live CNAME/AAAA/HTTPS behavior, then capture synchronized packet and return counters from a real Android client on the target ISP. No global TCP window, nftables or public DNS cutover is authorized by this report.

## v13–v14 isolated-route and DNS stability results (11 Nov 2026, 13:35–13:42 UTC)

### v13: actual TLS passthrough without changing production
- [Successful run #43030466038](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43030466038): the existing exact-host renderer staged candidate CoreDNS and Nginx route fragments in memory; both reversibility checks passed.
- On DE, a separately launched Nginx stream on **127.0.0.1 only** successfully completed certificate-verified TLS 1.3 to both `i.instagram.com` and `iglite-z.instagram.com`, using independently TLS-verified pinned destination IPv4 addresses. Unknown SNI was rejected.
- The test reported `production_configs_unchanged=true`, `public_dns_unchanged=true`, `android_e2e=NOT_TESTED`, and `client_sni_split=NOT_IMPLEMENTED`.
- An earlier [failed staging run #43030106632](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43030106632) exposed an incorrect module detection method. It was corrected by reading the actual validated nginx stream-module load directive before the green run. No live listener was replaced.

### v14: separate edge and direct upstream connection evidence
- A one-off `SERVFAIL` appeared for `i.instagram.com` during the [post-v13 public DNS check](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43030466038). That single response did not establish a persistent outage.
- [First five-round comparison #43031037309](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43031037309): **45/45** edge DNS-over-TLS queries across three exact domains and A/AAAA/HTTPS answered with `RCODE0`. Direct Quad9 queries from the GitHub runner returned several premature EOFs; that runner-to-Quad9 connection behavior is *not* proof of an edge resolver fault.
- [Green, corrected independent-source comparison #43031339156](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43031339156): the edge again returned **45/45 RCODE0**. Direct Quad9 from the GitHub runner showed repeated `EOFError` on some Instagram Lite queries. The CI now fails on repeated **edge** errors but records direct-Quad9 anomalies separately; synthetic tests verify that distinction.
- **Limitations:** an RCODE0 DNS response does not mean Instagram was proxied. The public policy was unchanged; the earlier verified `DIRECT_NOT_PROXY_ROUTED` classification remains the last evidence for those specific Meta names. These external probes do not test the Russian mobile network, real Android application or end-to-end SNI fragmentation.

### Next activation gate
Prepare only an owner-triggered, time-limited, exact-host public route canary after the user is ready to test the phone **during the same window**. Before any activation, verify baseline hashes, live ingress certificates, independent rollback, stable YouTube DNS answer, TCP/UDP scopes, and repeat the same checks after rollback. Do not reuse the v10 global TCP window-scaling experiment. Do not claim Smart DNS alone can split ClientHello before an upstream TSPU checkpoint.
