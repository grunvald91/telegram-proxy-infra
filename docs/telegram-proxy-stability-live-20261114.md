# Telegram proxy reliability revision — 2026-11-14

Scope: Russian edge `188.120.254.223`, foreign relay `89.125.90.101`.
All data below is scoped to the specific tests. No claim of completed Telegram Android upload/download E2E.

## Shared 443, existing services and DNS protection

The RU and foreign TCP/443 services are Nginx SNI dispatchers; they also carry
Telegram proxy connections, while legacy DNS-over-TLS remains on TCP/853.
This is **not** a reason to delete Telegram processes or replace the shared
Nginx or WireGuard setup.

- 13 Nov verified RU standard SYN+ACK exception and HTTPS remediation:
  [production #43470976337](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43470976337);
  source [PR #169](https://github.com/grunvald91/telegram-proxy-infra/pull/169).
- 14 Nov read-only RU/DE inventory:
  [#43562103814](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43562103814).
  RU postrouting chain had standard SYNACK exception preceding NFQUEUE;
  foreign postrouting had NFQUEUE queue 210 but no corresponding exception.
  Both existing installed Telemt binaries reported 3.4.23.
- Source-scoped foreign one-variable A/B/A:
  [#43562363288](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43562363288).
  External foreign 443 timed out before; during temporary source-restricted
  SYNACK accept the exact `cdn.servgo.ru` HTTPS returned TLS 1.3 and HTTP 200;
  after cleanup 443 timed out again. 8443/853 on DE and 443 on RU remained
  reachable during the experiment. The 120-second independently armed rollback
  was disarmed after verified manual cleanup.
- Guarded permanent foreign live patch:
  [#43562510416](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43562510416).
  Preserves ordinary SYN+ACK at the existing postrouting queue; later
  TCP packets retain existing NFQUEUE behavior. Independent six-minute
  rollback was armed before changes, backed-up original saved, external strict
  TLS verified `cdn.servgo.ru` and `mnebyvpn.site` HTTP 200, RU/DE 8443
  and DE 853 remained reachable, legacy DoT certificate and DNS response
  verified, then rollback timer disarmed after confirmation.
  The live foreign script to inspect/restore is
  `/usr/local/sbin/telegram-foreign-nfqws-rules`. See
  `scripts/telegram_foreign_synack_permanent_20261114.py`.
  **This does not imply that Telegram survives every ISP or uploads files.**

## Targeted Telemt 3.5.17 upgrade

Official upstream release:
https://github.com/telemt/telemt/releases/tag/3.5.17 (2026-11-08).

- The generic release asset `telemt` had a valid release SHA but caused
  `Exec format error` on x86_64 hosted Linux runner:
  [failed offline preflight #43562811226](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43562811226).
  No production change on that attempt.
- Subsequent controlled deployments use the **x86_64-linux-gnu.tar.gz**
  official artifact with SHA-256
  `0570762ddcd79530d666b09e955b955bb52c9e134cc8b8ed1a0f50ad28d58a0e`,
  verified **before** extraction. Each extracted executable is hashed, sent
  to the node over pinned SSH, verified again before any service change.
- [Foreign direct-sber #43562902254](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43562902254):
  `telemt-direct-sber.service` 3.5.17, two TCP listening sockets, guarded
  compatibility and website/DoT checks PASS.
- [Foreign media #43563089059](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43563089059):
  `telemt-rf-media.service` 3.5.17, two listening sockets, guarded
  compatibility and website/DoT checks PASS.
- [Russian main #43563197256](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43563197256):
  `telemt.service` 3.5.17, two listening sockets, guarded
  compatibility and website/DoT checks PASS.

The **shared `/usr/bin/telemt` binary remains 3.4.23**. Only these three
individual systemd units use
`/opt/telemt-3.5.17/telemt` via an isolated
`90-telemt3517-canary.conf` drop-in. Every change was preceded by an independent
6-minute rollback timer, verified, then committed with the rollback backup
preserved. The remaining units were not upgraded; the existing MTG,
tproxy-server, Nginx, WireGuard and CoreDNS deployments were not replaced.

Keep the 3 small `scripts/telemt_3517_*_canary_20261114.sh` scripts in source
control for exact audit/rollback. The one-off Actions workflows and temporary
source-scoped diagnostic script were intentionally removed from the proposed
main branch to avoid accumulating extra automatic SSH/Actions runs. Their immutable
Action logs remain linked here.

## WEB proxy

The two WEB proxy processes and underlying stock MTProxy backends were
healthy at read-only check
[#43560480233](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43560480233),
with both admin /readyz endpoints returning 200 and both backend ports reachable.
After DE SYNACK repair, standard external HTTPS on `cdn.servgo.ru` also returned 200.

These observations prove service/transport readiness only, **not**
an authenticated WEB relay session or compatibility with the user's Android
Telegram client. Upstream describes the Android implementation as
experimental; see https://github.com/telegramdesktop/tproxy-server .
Do not retire the already-working MTProto route on the basis of /readyz.

## Still required to validate actual stability

1. Real device: identify exact MTProto/WEB profile, client version, operator,
   connection stalls and timestamps on Wi-Fi and mobile data.
2. Real device: send and receive both small and larger media/files; record
   completion rates, time-to-first-byte, total transfer duration and resets.
3. Correlate the precise 1–2-minute test window to per-unit Telemt logs,
   Nginx upstream timers, WireGuard packet counters, TCP retransmission
   deltas and `ss -ti` on matching flows. Do not equate aggregate retransmits
   to Telegram loss; do not print client IPs or keys publicly.
4. Keep old and new Telemt in parallel until client session/media comparisons
   distinguish them; disable unused profiles only after live traffic mapping.
5. Native Telegram WEB support must be confirmed for the exact client build;
   a health check alone does not establish WEB proxy usability.

No paid subscriber migration was needed at the time of this revision.
