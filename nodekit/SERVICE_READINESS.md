# FI Nodekit: personal DNS, DNS SNI transport, Telegram MTProxy and AWG readiness

Status: **read-only diagnostics**, NOT production authorization.

Run the existing [fleet workflow](../.github/workflows/nodekit-fleet-bootstrap.yml)
manually with `country=fi`, `phase=service-audit`. This uses the previously
approved FI testing identity from `nodekit/fleet/fi.json`. It checks
`/var/lib/mnebyvpn-nodekit/fi-test-01` without writing to that directory,
starting systemd, touching NAT, opening ports, or changing subscriptions.

## Independent component gates

- **Personal DNS**: integrity of the staged Corefile, closed-by-default
  DNS/proxy candidate, staged TLS chain. This cannot prove that a certificate
  for `fi.mnebyvpn.site` covers personal hostnames
  `<token>.dns.mnebyvpn.site`; a matching wildcard/personal SNI,
  backend entitlement authorization, expiry/revocation and independent
  Android/iOS DoT client tests are mandatory. No common public resolver.
- **DNS SNI transport (NOT Telegram proxy)**: integrity of the staged Nginx stream configuration
  and its policy hash. No route is considered enabled until a signed
  allowlist, measured allowed/unknown SNI denial, external egress and
  service health are separately verified. Do not expose an open proxy.
- **AmneziaWG 3.1**: pinned node identity, staged AWG source and strict
  systemd watchdog/egress audit. Historical successful ephemeral
  runner E2E is **transport evidence**, not proof of a LIVE paid peer or
  subscription. Independent enrolled-controller key, live signed
  grant/revoke/expiry, stable external IP, mobile-client compatibility
  and strict release authorization remain required.
- **Xray REALITY** is a different VPN protocol; AWG readiness never
  claims a valid Xray profile. Xray access requires its own supervisor
  and end-to-end verification.

The CLI emits machine-readable `services.personal_dns`,
`services.dns_sni_transport`, `services.telegram_proxy`,
`services.amneziawg` with explicit blockers.
`controller_enrollment_candidate` is solely a preliminary, nonmutating
signal. It must not be interpreted as `enrolled` (a trusted database
challenge/response is required).

**Critical invariant:** `automatic_publication_authorized` and
`services.*.ready` remain false while independent signed external proofs
and DB release/authorization gates are missing. Green CI or `FLEET_STAGE_COMPLETE`
can never override those booleans. The script makes no release decisions
and cannot be used as a caller-supplied positive evidence blob.

## FI217 actual read-only findings, 2026-11-23

Independent FI inspection (after fixing incomplete diagnostic dependencies and
separating unrelated AWG errors):
[run 45222896888](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/45222896888)
**SUCCESS**. No existing clients or services changed.

- `personal_dns.local_candidate_verified=true`: local candidate + TLS stage
  present; `personal_fqdn_tls_verified=false`, `entitlement_enforcement_verified=false`,
  `independent_external_e2e_verified=false`; not ready.
- `dns_sni_transport.local_candidate_verified=true`, `route_count=0`,
  no signed policy / external allow-and-deny E2E; not ready.
- `telegram_proxy.local_candidate_verified=true` (staged Telemt 3.5.17),
  `telemt_installed_verified=false`, no active listener,
  no personalized grants/revoke or actual Telegram mobile E2E; not ready.
- `amneziawg.blockers=["awg_independent_inspection_error"]`: the separate
  AWG audit failed while DNS/Telemt inspection passed. **Do not infer AWG
  tunnel failure from this diagnostic result**; its production behavior must
  be evaluated separately.
- `automatic_publication_authorized=false` across all services.

**Immediate FI product priorities:** complete and independently test personal
DoT (policy, per-entitlement credentials, TLS, revoke and externally verified
Android connection) before controlled public release; then activate the
reviewed FI Telemt service with per-subscriber signed access, independent
Telegram message/file E2E and expiry/revoke. Do not use successful RU/DE
Smart DNS or German Telemt as evidence for Finland. Keep live FI AWG,
RU/DE DNS, existing MTProxy and customer entitlements untouched.

## Live evidence at time of implementation

- Temporary FI external AmneziaWG runner passed on 2026-11-18:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44255522426
- FI controller-audit on 2026-11-18 showed **NO controller public
  key installed**, no database enrollment verification, all customer
  access turned off:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44268999147

## Steps still needed to connect real clients

1. Provision the signer in a root-only segregated directory on the **existing
   controller 188.120.254.223**, never on a second controller, approve its public SPKI SHA256 out-of-band;
   never put the signing key in GitHub Actions, on the customer VPS or in an AI prompt.
2. Register `fi-test-01` through the existing one-use challenge/response
   against the central PostgreSQL inventory. Never equate bootstrap with enrollment.
3. Prove one signed AWG grant + actual external client E2E + local expiration and
   revoke; separately prove per-customer DNS DoT, Telegram Telemt MTProxy,
   internal DNS SNI transport and Xray.
4. Implement independent evidence collection, country confirmation,
   guarded per-service release and rollback with current customer
   subscriptions untouched. No blanket enable for all services.


## Clarification: central controller and Telegram proxy

The single central controller remains **RU188 188.120.254.223** (website,
Telegram bot, PostgreSQL, subscription/expiry workers). There is **no new
controller host**. On FI, `dns_sni_transport` refers only to a staged Nginx
SmartDNS component; the Telegram user-facing proxy is `telegram_proxy`
(Telemt/MTProto). A verified **dormant Telemt candidate** is staged on FI, but a running, customer-authorized Telegram proxy is NOT yet installed or E2E-verified.
This is audit schema **v2**, not evidence of customer release. See
[CONTROLLER188_TELEGRAM_PROXY.md](CONTROLLER188_TELEGRAM_PROXY.md).
