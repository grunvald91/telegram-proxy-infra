# Automatic MNEBYVPN website deployment

The **public informational website only** is automatically updated from
[`grunvald91/Mnebyvpn` main](https://github.com/grunvald91/Mnebyvpn/tree/main)
by [`mnebyvpn-main-auto-public.yml`](../.github/workflows/mnebyvpn-main-auto-public.yml)
in this infrastructure repository.

## Trigger and verification

- GitHub Actions checks the source main branch **every 15 minutes**, and can be
  launched manually with **Run workflow**. Deployments are not necessarily immediate
  after merge: GitHub scheduled jobs may start later than the nominal interval.
- The most recent successful `Offline code and database contracts` check must
  be an ancestor of the target source main SHA; website runtime dependencies
  (`apps/web`, `packages`, `db`, `package.json`, `tsconfig.json`)
  must be identical to the tested source. A failed or absent CI **skips** deployment.
- The workflow uses only this repo's existing
  `SERVER188_SSH_PASSWORD` Actions secret; do **not** copy SSH credentials into
  the public MNEBYVPN source repository.
- The remote `/opt/mnebyvpn/public/active_sha` records the successful commit.
  When it already matches main, no images are built or restarted.
- One Actions workflow checks the source rather than duplicating its Node/SQL
  test suite. Each real code change is tested once by the MNEBYVPN CI.

## Scope and safety

This deploy uses the existing isolated services on server188:

| Service | Endpoint | Changes |
|---|---|---|
| Test web | `127.0.0.1:8791` | Existing staging installer verifies source and schema, builds image |
| Public web | `127.0.0.1:8792` | Replaced only after canary health/security check |
| Temporary public canary | First unused localhost port among `18793–18795`, `28793–28794` | Starts for validation, then removed |
| PostgreSQL | `127.0.0.1:55433` | Reused; migrations handled only by existing stage installer |

Only the named `mnebyvpn-stage-web` and `mnebyvpn-public-web`
containers may be restarted by this workflow. It doesn't reconfigure Nginx,
ACME, TLS, DNS, routes, firewalls, Telegram relay, WireGuard, other
containers, the BandSongbook Sync listener, or proxy services. The stage
installer applies forward migrations only to its **staging** database; it
does not automatically modify the public read-only database schema.
**A later website migration requiring public DB DDL needs a separate reviewed
migration process before main is changed.**

The production `/opt/mnebyvpn/public/web.env` must already exist and
explicitly keep OIDC login, trial, checkout and unverified network features
**disabled**. Any configuration mismatch aborts before promotion.
A new image is first tested on an unoccupied high localhost port. On failure after switching port 8792,
the previous image is restarted and the active SHA is not updated.
`/healthz` is expected to return 200 and **`/readyz` 503**; readiness 503
is intentional until commercial release requirements are met.

## Diagnosing an unsuccessful run

1. Check [the auto-deploy workflow](../.github/workflows/mnebyvpn-main-auto-public.yml)
   in GitHub Actions for the source SHA, passed CI SHA and failure step.
2. If the source CI gate skips it, fix or rerun MNEBYVPN's
   `Offline code and database contracts` workflow on the latest website code.
3. If the remote preflight or canary fails, do not bypass its checks.
   The old public image should remain online.
4. If localhost port 8792 is healthy but `https://mnebyvpn.site` is unreachable,
   diagnose existing external DNS/TLS/443 separately. This automation
   **cannot** fix a network block or domain routing problem.

## Limits

This is **automatic deployment of the informational web frontend/backend**,
not a switch to commercial availability. Actual customer payments, VPN
provisioning, DNS, Telegram OIDC and publication of prices remain behind the
separate existing release gates. Automation is deliberately fail-closed.
