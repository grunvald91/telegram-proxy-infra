# FI Nodekit: separate DNS, SNI proxy and AmneziaWG readiness audit

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
- **SNI proxy**: integrity of the staged Nginx stream configuration
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
`services.sni_proxy`, `services.amneziawg` with explicit blockers.
`controller_enrollment_candidate` is solely a preliminary, nonmutating
signal. It must not be interpreted as `enrolled` (a trusted database
challenge/response is required).

**Critical invariant:** `automatic_publication_authorized` and
`services.*.ready` remain false while independent signed external proofs
and DB release/authorization gates are missing. Green CI or `FLEET_STAGE_COMPLETE`
can never override those booleans. The script makes no release decisions
and cannot be used as a caller-supplied positive evidence blob.

## Live evidence at time of implementation

- Temporary FI external AmneziaWG runner passed on 2026-11-18:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44255522426
- FI controller-audit on 2026-11-18 showed **NO controller public
  key installed**, no database enrollment verification, all customer
  access turned off:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44268999147

## Steps still needed to connect real clients

1. Independently provision a trusted controller's private Ed25519 signer
   on a protected controller host, approve its public SPKI SHA256 out-of-band;
   never put the signing key in GitHub Actions, on the customer VPS or in an AI prompt.
2. Register `fi-test-01` through the existing one-use challenge/response
   against the central PostgreSQL inventory. Never equate bootstrap with enrollment.
3. Prove one signed AWG grant + actual external client E2E + local expiration and
   revoke; separately prove per-customer DNS DoT, SNI proxy and Xray.
4. Implement independent evidence collection, country confirmation,
   guarded per-service release and rollback with current customer
   subscriptions untouched. No blanket enable for all services.
