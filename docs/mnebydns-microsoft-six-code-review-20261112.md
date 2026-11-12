# MNEBYDNS — Microsoft exact-host rollout code review, 2026-11-12

Scope: [six-host orchestrator](../scripts/mnebydns-microsoft-six-permanent-20261111.py),
[owner reconciler](../scripts/mnebydns-owner-domain-controller-20261110.py),
[launch workflow](../.github/workflows/mnebydns-microsoft-six-permanent-20261111.yml),
and [9 offline regression tests](../scripts/tests/test_mnebydns_microsoft_six_review.py).

## Verified production inventory as of 2026-11-12 12:55 UTC

Sources:
- [Canonical PostgreSQL + actual live CoreDNS and Nginx audit, run 43222269999](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43222269999)
- [Independent exact-host DB/config cross-check, run 43081463433](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43081463433)
- [First failed unattended Microsoft batch, run 43080143386](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43080143386)
- [Resumed rollout and Bing PROBING failure, run 43082640435](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43082640435)

| Exact FQDN | DB | DNS + Nginx exact owner marker | Origin DB metadata |
|---|---|---|---|
| copilot.microsoft.com | ACTIVE | present | valid IPv4 /32 |
| software-static.download.prss.microsoft.com | ACTIVE, historical ACTIVE_ROUTE_METADATA_INVALID | present | valid IPv4 /32 |
| xbox.com | ACTIVE, historical ACTIVE_ROUTE_METADATA_INVALID | present | valid IPv4 /32 |
| xboxdesignlab.xbox.com | ACTIVE | present | valid IPv4 /32 |
| bing.com | FAILED, INTERRUPTED_OWNER_DEPLOY | absent | null |
| microsoft.com | FAILED, CANARY_PREFLIGHT_OR_DEPLOY_FAILED | absent | null |

All four exact-host owner config markers and matching Nginx upstream IPv4 pins exist in the live stable checkpoint. That does **not** prove an entire Microsoft website, account login, redirect chain, Xbox service or dynamic CDN functions on actual customer devices.

## Findings and dispositions

**P0 — Owner state machine continued after unresolved previous host.**
In the interrupted batch Bing got stuck in PROBING; the orchestrator recorded an incomplete host and attempted another one, which was then deferred. Under more concurrent operations, continuing from an unfinished active transition is unsafe.
Fix: `verify_failed_transition` now explicitly refuses unresolved PROBING/CONFIRMING/ACTIVE or checkpoint drift, requires verified rollback before continuing, and aborts instead of silently advancing. Nine isolated mocked tests cover error branches and no subsequent host after failure.

**P0 — Code review changes could cause an unintended full six-host production rollout.**
Previously the workflow's `push` trigger unconditionally ran `release` whenever its source or YAML changed. That makes review fixes have a network-change side effect.
Fix: code and test changes run only offline checks; a real rollout is gated by an explicit `workflow_dispatch` deployment input or a separately reviewed `data/mnebydns-microsoft-six-rollout-trigger-20261112.txt` change.

**P1 — Two ACTIVE health metadata flags disagree with actual source metadata.**
The independent read-only PostgreSQL audit shows valid IPv4 host /32 origin fields and live exact Nginx IP pins for both affected hosts. The `pg_inet_host` code now accepts PostgreSQL's `/32` notation; the flags may predate the fix or an intermittent health check. Do not clear them without a fresh verified origin TLS/DoT health pass. An `ACTIVE` DB state plus marker is not functional proof.

**P1 — Route certificate and DoT checks are not complete end-user acceptance tests.**
The six-host orchestrator's `health()` invokes DoT record checks and RU→DE public TLS with original SNI only. It does not verify the HTTP response, redirects, Microsoft sign-in, all network dependencies, IPv6, HTTPS/SVCB answers at every device, or QUIC behavior. Keep claims scoped to verified exact-host routing. This review does not add broad wildcard rules or automatically include unlisted Microsoft subdomains.

**P2 — Failed and intermediate statuses are not owner-operable in all cases.**
Telegram admin surfaces individual status and permits PENDING/FAILED approval, but stuck PROBING is recovered by the owner reconciliation worker and verified rollback, not a blind re-queue button. Consider an audited owner-only “diagnose / retry after clean rollback” action with definitive error codes.

## Safety and release gate

- Merge this review fix only after all offline regression tests and existing owner route tests are green.
- The review merge must NOT activate, replace or disable any Microsoft, Gemini, Claude, VPN or Telegram-proxy route.
- Actual retry of Bing / Microsoft apex requires a separately reviewed run and current stable checkpoint, no other active domain transition, verified egress and rollback.
- Claims about exact Microsoft hosts are based on the source-listed six names only.
