# MNEBYDNS first 100 research candidates — production evidence (2026-11-15)

This document records the immutable original alphabetical *PENDING* inventory
from GitHub Actions run [43682373080](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43682373080):
100 domains, from `6pm.com` through `claudemcpcontent.com`.

## Verified outcomes (not an assertion that all 100 can be routed)

| Current outcome | Domains | Evidence |
| --- | ---: | --- |
| Newly ACTIVE in production PostgreSQL and in both exact-host CoreDNS/Nginx routes | **12** | [43682964258](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43682964258), [43683682889](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43683682889), [43684108733](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43684108733) |
| Covered by older live DNS rule; research DB row still PENDING | **1** | `chatgpt.com` returns RU188, [43682786608](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43682786608), [43684108733](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43684108733) |
| Verified DE HTTPS but public RU188 ingress TLS failed; stays PENDING | **3** | `arduino.cc`, `avira.com`, `bluehost.com`, [43683987282](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43683987282) |
| Successful foreign HTTPS not confirmed in first100 preflight; stays PENDING | **24** | [43682964258](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43682964258) |
| Differential Russian access restriction not confirmed by the first100 criteria; stays PENDING | **60** | Preflight initially classified 73 under this condition; 13 were separately tested for RU TCP/TLS errors, of which 10 were activated and 3 require TLS fixes: [43682964258](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43682964258), [43683332217](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43683332217) |

**Totals:** 12 ACTIVE + 88 PENDING = 100 original research rows. The five categories above sum to 100.

### Activated 12 exact hosts

`artifacts.elastic.co`, `brickset.com`, `account.mongodb.com`,
`alberta.ca`, `analog.com`, `ansys.com`, `axiomtek.com`,
`badoo.com`, `badoocdn.com`, `bosch.de`, `bumble.com`,
`census.gov`.

The final live audit [43684108733](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43684108733)
verified all 12 have PostgreSQL `ACTIVE`, the expected exact CoreDNS and
Nginx markers, A answers of `188.120.254.223`, and successful HTTP 2xx/3xx
via RU188. It also verified existing Gemini, Claude, Grok, X, TikTok and ChatGPT
DoT A answers remain RU188.

### Routing, safety and limitations

The established DNS entrance is **188.120.254.223 (RU)**; **89.125.90.101
(DE)** is the SNI proxy. The former exact-host renderer and regression
checker erroneously demanded public A answers of DE89. The successful isolated
one-shot deployment corrected this without rewriting pre-existing rules.
The permanent renderer and checker source fix is in this PR.

The 60 non-differential names are **not asserted to be accessible from every
Russian ISP**. The 24 with no foreign success are **not asserted to be
inaccessible worldwide**. A trusted full TLS/HTTPS route is required before
activation; automatically proxying all 100 would be misleading and could
break functioning clients. The three public-ingress TLS failures require
separate origin/SNI investigation rather than disabling certificate checks.

The research-only PENDING rows were intentionally not mislabelled ACTIVE.
This inventory has been processed; subsequent batches should use an explicit
frozen cursor/snapshot rather than repeatedly selecting the first 100 PENDING.
