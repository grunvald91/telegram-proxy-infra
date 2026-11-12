# MNEBYDNS Instagram Lite exact-host SNI Window=4 — 11 November 2026

## Scope and outcome

This is the **Instagram Lite** hostname `iglite-z.instagram.com`, not evidence
of a working official/full Instagram application. Every live test is bounded:
temporary public DoT rewrite, exact SNI Nginx route to a TLS-verified Meta
origin, DE public IPv4 TCP/443 SYN-ACK Window=4, and independent systemd
rollback. User's Android/ISP endpoint did **not** participate.

The latest [GitHub Actions live canary #42963433765](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42963433765)
**completed successfully as a controlled server test**, not a confirmed
censorship bypass. Key independently logged results:

| Check | Actual result |
| --- | --- |
| DoT `A` for exact Lite host | `A_EXACT_DE` |
| DoT `AAAA` | `NO_ALIAS_OR_IPV6` |
| DoT `HTTPS` (type 65) | `NO_ALIAS_OR_IPV6` |
| DoT `SVCB` (type 64) | `NO_ALIAS_OR_IPV6` |
| DoT `CNAME` | `NO_ALIAS_OR_IPV6` |
| TLSv1.3 DE → verified Meta origin | PASS |
| Global DE IPv4 TCP/443 SYN-ACK Window=4 | ACTIVE during 35-second pilot |
| nft matching SYN-ACK counter | 8 (not individual TLS sessions) |
| Runner → DE public TCP/443 / Lite TLS | `NOT_VERIFIED_TimeoutError` |
| Exact test-owned nft table gone | `true` |
| Original Corefile and Nginx bytes restored | `true` |
| Nginx / DNS service active after rollback | `true` |
| Unchanged Android Instagram Lite feed | NOT TESTED |

Matching an nft SYN-ACK rule only proves rule hits. It does **not** demonstrate
that the Android client segmented its ClientHello, that the ISP let SNI through,
that full TLS succeeded from an external client, or that Instagram content loaded.
The Runner's TCP/443 timeout is **not** independently attributable to Russian
DPI/SNI: earlier Runner→DE TCP/443 baseline also timed out before changing
Window=4. DE→Meta validated TLS is a different connection.

## Measurements, review gates and failure prevention

- [Offline actual kernel TCP segmentation #42960390217](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42960390217)
  confirmed first TLS client data segment changed from 1448 to 4 bytes with
  synthetically scoped port 18443; checksum stayed valid, and deletion restored
  the original segment size. Not a live mobile measurement.
- [Live short global DE 443 canary #42960882311](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42960882311)
  ran 35 seconds, one SYN-ACK rule match, automatic rollback and service checks.
- [Five-type DNS negative fixture + kernel tests #42963248346](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42963248346)
  passed. Rejects rogue Meta IPv6 AAAA, HTTPS/SVCB service bindings, CNAME
  aliases, additional A answers, wrong DNS questions, truncation and compression
  pointer cycles. Live DoT replies match the required exact routing state.
- Fail-closed attempts and recovery: [#42961569772](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42961569772)
  refused to overlap a previous watchdog; [#42962244973](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42962244973)
  stopped on `127.0.0.1:853` (CoreDNS binds DE public IPv4 only);
  [#42962481978](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42962481978)
  refused to overlap a second watchdog. Rollback/postchecks were successful.
- The live trial isolated each version's timer and nft table and required
  checkpoint-matching DNS/Nginx files; it never globally flushed nftables or
  changed unrelated DNS routes.

## Unresolved gates before calling it an Instagram bypass

1. Actual device→DE public IPv4 TCP/443 flow with the unmodified Instagram
   Lite Android app on the user's ISP path, correlated by complete
   SYN/SYN-ACK/ACK and first TLS packet metadata. A Runner is not a replacement.
2. Validate actual client TLS (not just DE→Meta) and that the app loads feed
   content. The browser/Runner TLS timeout remains unresolved.
3. Assess possible application DoH, hardcoded Meta IP, QUIC/UDP443, cached
   DNS and direct IPv6 paths outside this exact DoT owner hostname. Five-type
   DoT correctness does not prove that every app connection uses that DoT
   resolver.
4. Full Instagram, `i.instagram.com` and `graph.instagram.com`, require
   separate justified routing and app tests; exact Lite evidence cannot be
   generalized to those hosts.

**Current production state:** experiments rolled back, no exact Lite DNS/Nginx
route retained, no global Window=4 rule retained; PR remains a draft.


## Follow-up 11 Nov: direct TCP/443 baseline, NFQUEUE210 passive diagnosis

- [Read-only DE packet capture #42964387793](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42964387793): from GitHub Runner, TCP/853 and its verified TLS 1.3 work; two TCP/443 attempts time out. DE sees 10 inbound TCP SYNs, **0 emitted SYN-ACK** in the scoped interface capture, and no TLS payload. Capture scope assumes SSH and test socket egress share a public IP; this assumption was not independently verified, although captured SYN activity is clear.
- [DE firewall audit #42964625263](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42964625263): the existing \`inet telegram_nfqws/post\` hook queues selected outgoing TCP source-port-443 response packets to **NFQUEUE 210** with \`bypass\` flag. The queue has an active owner. Other inbound filters exist; their effect on this exact flow is not proven.
- [Read-only NFQUEUE210 baseline #42965392820](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42965392820): four TCP/443 Runner probes timed out; queue210 handler remained present and global queue rule counters rose by 22 packets over 14 seconds. These counters **are not per-Runner flow** and cannot prove who dropped SYN-ACK.
- [Read-only kernel queue and SYN-RECV #42965663506](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42965663506): another six Runner probes timed out over three phases; first-phase DE capture saw 10 SYN and 0 SYN-ACK, passive NFQUEUE210 counter increased but includes background traffic. Queue total was 0 at both sample endpoints; \`queue_dropped\` delta=0 and \`user_dropped\` delta=0. Kernel \`ss\` saw maximum **2 half-open SYN-RECV** connections associated with SSH peer during the 13-second observation. No queue overflow/drop counter increased, but this cannot distinguish worker verdict, routing, or other egress handling.
- The proposed **one-peer rule change of NFQUEUE210 was NOT run**. Creating the live GitHub Actions workflow for that experiment was blocked by platform security; permission alone does not override it. The unreviewed and never-deployed bypass script was deleted from the draft PR, while passive diagnostic scripts remain.
- No production DNS, Nginx, firewall or queue rule was modified by the read-only diagnostic runs. **Do not interpret this evidence as success of SNI fragmentation or as mobile ISP filtering.** We still need a permitted per-flow egress attribution method and then an actual Android→DE app trial before concluding.
