# v15 implementation review, 11 November 2026

Reviewed base: [`ffadc399`](https://github.com/grunvald91/telegram-proxy-infra/commit/ffadc399585fcda4ebfb87f48a0a755ef4d98421).
All corrections remain in draft PR [87](https://github.com/grunvald91/telegram-proxy-infra/pull/87).
No live phone canary or production deployment is part of this review.

## Corrected defects

| Priority | Defect in reviewed implementation | Correction |
| --- | --- | --- |
| P1 | REDIRECT chooses an interface address; the proxy binds the explicit edge address. They can differ when the edge IP is secondary, breaking all selected peer connections. | Use explicit IPv4 DNAT to the bound edge IP and dedicated port. The network lab now deliberately makes EDGE secondary. |
| P1 | A complete first TLS record was treated as the complete ClientHello. A valid ClientHello fragmented across TLS records could release the tiny window before SNI and be missed by the observer. | Bounded TLS-record reassembly for both proxy and observer, preserving the original byte stream and physical TCP-stream SNI offsets. |
| P1 | Failed nft probes could be interpreted as an absent table, while a deactivating worker could be interpreted as stopped. Cleanup could print VERIFIED without establishing restoration. | Require a successful JSON table listing and explicit service MainPID/ActiveState verification. Errors still permit attempts to stop the worker and restore configurations, but never produce VERIFIED. |
| P1 | An unrelated listener occupying the port could pass readiness. An accept-loop failure could leave a listening but non-serving process alive. | Check the exact service PID and bound address, monitor health during the trial, and stop/fail the worker on unexpected accept errors. |
| P1 | The in-process rollback, configuration watchdog and full watchdog could race on the same staging files. The live controller could continue configuration activation after independent cleanup. | Reentrant per-process locking plus a cross-process flock, guarded configuration activation, and a durable cleanup-started marker that prohibits late activation/READY. |
| P2 | An eight-byte rewrite could increase an already smaller or zero native receive window. | Only reduce native windows larger than eight bytes. |
| P2 | The queue exemption validator accepted a matching bit check placed after the queue verdict. | Require the exact mark exclusion before queue210. |
| P2 | An error after starting capture but before READY could skip observer teardown. | Cover all post-start readiness/deadline work with capture finalization. |

## Reproduction and checks

- Eight selected new regression tests were run against the old receiver,
  observer and controller sources: **7 failures and 1 error**, reproducing the
  reviewed defects rather than merely asserting new implementation strings.
- **66 local tests passed:** 25 observer, 13 v11 route/signal/recovery,
  10 DNS wire, 10 receiver, 8 controller. This includes real local sockets,
  relay half-close/data integrity, and cross-process cleanup locking.
- Workflow YAML, embedded shell syntax, Python compilation and whitespace
  checks passed locally.
- The expanded isolated network lab requires successful TLS/application
  exchange and SNI TCP segmentation for both ordinary and TLS-record-fragmented
  ClientHello, with EDGE configured as a secondary interface IP. CI results
  are linked from PR 87 after completion.

## Sources and limits

Linux REDIRECT selects the incoming interface's first IPv4 address:
[`nf_nat_redirect_ipv4`](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_nat_redirect.c).
TLS handshake messages may span records:
[RFC 8446 section 5.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1).

The protocol parser retains its bounded 8192-byte prefix limit. The tiny
initial window can add latency; the test connection retains its 64-KiB clamp.
The mechanism is IPv4/TCP only, and other connections behind the selected NAT
IP also enter the listener. Linux lab results do not establish Android/ISP
behavior, QUIC fallback, Instagram login/feed functionality or DPI bypass.
