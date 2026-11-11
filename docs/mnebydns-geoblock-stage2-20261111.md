# MNEBYDNS — Stage 2: paired RU/DE read-only screening (2026-11-11)

## Purpose
From the 506 exact-name **research-only** entries already queued in the RU database, select 39 explicitly cited names in the supplied study. Measure whether **one fixed public IPv4 origin** responds differently to unauthenticated HTTPS requests from the Russian server and the foreign server.

This stage **does not** activate DNS routes, edit CoreDNS/nginx, update PostgreSQL statuses, touch firewall/network services, or route customer traffic. The PR check validates only source and policy; after merging main, the GitHub Actions workflow runs the cross-country network probe and uploads JSON and Markdown results.

## Method
1. Validate 39 exact FQDNs against the 523-name research TSV with status PENDING_RESEARCH.
2. On DE, resolve each host's public A records, rejecting private/reserved/self-referential addresses. Try up to three origins with system-trust TLS 1.2/1.3 validation and original SNI. No MITM, credentials, redirects, JS execution, session or file download.
3. Send **the same public origin IP** and original hostname to the RU probe. Compare TCP/TLS result and one minimal HTTP/1.1 GET / status with Host/SNI.
4. Report differences as *candidates for investigation*. A 403/451 from RU and 2xx/3xx from DE is **not proof** of national geoblocking. TLS timeout differences may reflect path or TSPU rather than geoblock. Two 200 responses do not prove application feature access.
5. Store `stage2-results/differential.json` and `stage2-results/report.md` in a 14-day GitHub Actions artifact. No end-user browser compatibility, payment/login, anti-bot, QUIC or video streaming inference.

## Release gate
The existing MNEBYDNS owner route controller already requires per-host canary, health checks and rollback. This probe **must not** trigger `APPLY_REQUESTED` or `ACTIVE` automatically. Before any activation:
- check whether each host is already covered by live shared rules, avoid overlapping DNS and Nginx exact/wildcard maps;
- verify DE origin TLS and RU→DE **public ingress** TLS for the requested hostname (not just RU direct origin);
- check A, AAAA, HTTPS/SVCB, CNAME behavior, application dependencies, ECH and QUIC/fallback;
- preserve existing Gemini, Claude, Grok, X, TikTok, Discord, Antigravity and Russian service paths;
- maintain separate signed/verified owner canary and tested rollback, never bulk-enable 506 destinations.

## Reproducibility
`python3 scripts/mnebydns-geoblock-stage2-probe-20261111.py --self-test` validates catalog membership and strict origin constraints offline. The live GitHub Actions run requires existing scoped SSH secrets but prints neither credentials nor customer data.

Studies/related implementation:
- [Research inventory](mnebydns-geoblock-research-20261110.md)
- [Project owner exact-host controller](../scripts/mnebydns-owner-domain-controller-20261110.py)
- [Known RU→DE SNI reachability problems](https://github.com/grunvald91/telegram-proxy-infra/pull/56).
