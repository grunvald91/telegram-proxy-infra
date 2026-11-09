# MNEBYDNS — Instagram and Threads mobile PCAP cross-check (2026-11-09)

## Decision
**Status: NOT FIXED.** Temporary Meta ingress canary was automatically reverted; stable working DNS/VPN routes preserved. Do not promote this canary to permanent production from server-only tests.

Evidence (read-only GitHub Actions runs):
- Meta 28-minute guarded canary: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42583884583
- During-canary RU/DE status: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42586825905
- 08:18–08:23 UTC journal classification: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42587071127
- Successful post-canary rollback and DNS cause: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42587353125
- Read-only Meta upstream DNS comparison: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42587523019

## Source capture
Owner-supplied Android PCAPdroid capture named `PCAPdroid_09_нояб._11_19_02.pcap`, captured **2026-11-09 08:19:03–08:21:27 UTC (11:19–11:21 Moscow)**. The raw PCAP is NOT uploaded to the repository.

- 107 outgoing TCP:443 flows to RU Meta ingress; 105 had zero inbound TCP application payload; 2 had inbound application payload.
- TLS ClientHello cleartext SNI count: `i.instagram.com` 40; `i-fallback.instagram.com` 31; `test-gateway.instagram.com` 26; `iglite-z.instagram.com` 6; `graph.instagram.com` 1; `z-m-gateway.facebook.com` 1; two unique `*-netseer-ipaddr-assoc.*.fbcdn.net` 1 each.
- Client TCP SYNs mostly received SYN/ACKs and the TLS ClientHello was ACKed, but ServerHello/application bytes were not observed for the main Instagram domains. This is not proof of where the response was dropped.
- 12 outgoing UDP:443 flows (85 client packets), 0 return packets; the canary has no UDP/443 QUIC listener.
- The packet capture cannot definitively attribute every connection to Instagram versus Threads or distinguish operator DPI from a mid-path/inbound flow fault by itself.

## Correlation with production canary
- Guarded Meta canary deployed at about 08:09 UTC, due to revert at 08:37:25 UTC.
- Capture 08:19–08:21 UTC occurred DURING that canary. Thus absence of DNS routes cannot explain the main failure in this capture.
- During-canary server loopback TLS 1.3 handshake checks passed for `i.instagram.com`, `iglite-z.instagram.com`, `test-gateway.instagram.com`, and `threads.com`.
- Separate checks at ~08:35 UTC found one intermittent local timeout for `iglite-z.instagram.com`; do not overstate server reliability.
- DE Meta sidecar journal in PCAP window contained **two host-not-found (DNS code 3) failures**, and they referred to ephemeral `*-netseer-ipaddr-assoc.xy.fbcdn.net` tracking names, NOT the main Instagram API SNI.
- Quad9 and Cloudflare each returned A answers for `graph.instagram.com`, `i-fallback.instagram.com`, `i.instagram.com`, `iglite-z.instagram.com`, `test-gateway.instagram.com`, and `threads.com` when tested later. The two netseer names returned no A records.
- After deadline the German DNS/Nginx/proxy matched the stable checkpoint, temporary Meta sidecar was gone, and Russian Nginx returned to its pre-canary SNI file; no production persistence was attempted.

## Main hypotheses (NOT verified)
1. Mobile-network or ingress-path handling of TLS ClientHello with Meta SNI. The SNI is exposed by the DNS+TLS passthrough architecture and could be filtered. Server loopback success does not identify a mobile-network cause.
2. Intermittent backend origin failures or rate/connection limits during bursts from Android. Need synchronized server-side connection outcomes and error counters, not only later loopback probes.
3. QUIC requests cannot work through the current TCP-only SNI proxy. Even a fully working TCP path would not establish that the Android apps fall back reliably.

## Next controlled experiment
- Keep stable five/ChatGPT production routes untouched.
- On owner's test device: VPN OFF, system Private DNS ON; run separate Instagram-only and Threads-only short tests on mobile then Wi-Fi if available.
- For 60–90 seconds synchronized with each user test, gather **aggregated** ingress TCP SYN, ClientHello progress and server-to-client TLS response counts on RU, plus TCP upstream outcomes on private DE. No raw packet payload, cookies, credentials, account IDs or persistent source IPs.
- Compare `i.instagram.com`, `i-fallback.instagram.com`, `test-gateway.instagram.com`, `iglite-z.instagram.com`. Confirm exact failure stage before choosing any fix.
- Treat QUIC/UDP as a separate architecture task. No blanket UDP/443 open proxy or unauthorized wildcard backends.
- Accept a Meta canary only after actual phone app success, complete end-to-end TLS and cert validation, stable checks, and tested rollback. Do not claim a DNS-only bypass is universally achievable.

**Do not change production from this read-only report.**
