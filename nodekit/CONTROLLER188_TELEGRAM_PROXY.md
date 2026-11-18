# MNEBYVPN architecture contract: existing RU188 controller / Telegram MTProxy

Status: verified against the existing repository deployment and payment code.
Live readiness of the hosts must be checked separately via
`.github/workflows/mnebyvpn-controller188-telegram-readonly.yml`.

## Existing authority: DO NOT create a second central controller

- **RU188**: `188.120.254.223` is the **existing central MNEBYVPN controller and RU ingress**. The production website, Telegram bot, PostgreSQL, VPN entitlement/expiry workers and publishing logic reside in this existing deployment. Any new Nodekit registrar, private Ed25519 signer and AWG delivery worker must be isolated root-only components **on RU188**, not on a new dedicated server, public bot process, browser or FI.
- **DE89**: `89.125.90.101` is the existing foreign egress node serving Xray/VLESS and Telegram proxy Telemt (including `direct-ozon`). The existing RU188↔DE89 WireGuard tunnel and application/personal DNS gateways remain untouched.
- **FI**: `fi-test-01`, `217.11.167.91`, `fi.mnebyvpn.site`, is an independently staged **new** testing node, not the central authority. It cannot create subscription rights, approve inventory or distribute controller secrets.

The reviewed root-only controller signer must be provisioned locally on 188
`/root/mnebyvpn-controller` only after independent fingerprint approval and
a read-only inspection of the existing service boundaries. The public website
and workers must never get the signing private key. Do not copy it to DE89, FI,
GitHub Actions or ChatGPT. Do not restart/change the existing website, bot,
PostgreSQL, 188/89 routing or payment workers to accomplish enrollment.

## Definition of “proxy” in Nodekit

**Customer-facing proxy = Telegram MTProto proxy using Telemt (or a separately
reviewed MTProxy-compatible implementation).** It is not an arbitrary SNI
forwarder, HTTP CONNECT service or VPN tunnel.

The legacy inventory spec v1 has a component named `sni-proxy`. Its staged
`dns-proxy/nginx.conf` is actually an **internal Smart DNS SNI transport**,
not Telegram MTProxy, and has zero confirmed Telegram users or working
Telegram connections. To preserve the already staged FI spec and immutable
identity, **do not rewrite the existing `fleet/fi.json`, manifest, port or
hashes in-place**. Add new Telegram-specific provisioner/service-grant
contracts in a later reviewed schema v2. Existing SNI candidate remains
off and is audited only as `dns_sni_transport`.

`service_readiness.py` schema v2 reports separately:
- `personal_dns`: per-user DoT; no public unauthenticated DNS.
- `dns_sni_transport`: internal Nginx stream candidate; NOT Telegram proxy.
- `telegram_proxy`: Telemt MTProto, currently **not staged on FI**.
- `amneziawg`: AWG3.1 independent VPN; VLESS/REALITY also separate.

For Telegram proxy on FI require: verified Telemt binary + config in an
isolated service, secret-free external client integration test (Telegram
handshake, send/receive/media), per-entitlement provisioner using existing
`Mnebyvpn/packages/web/src/telegram-proxy-provisioning.ts` contract, one
user's own secret only, expiry/refund/revoke E2E, zero default/public shared
credentials and an independently approved release. Existing DE89 Telemt users
and both DE89/RU188 routes must remain working.

## Sources of truth in code

- Existing RU188 deployment:
  `.github/workflows/mnebyvpn-current-deployment-audit.yml`.
- Existing customer-specific Telegram proxy issuing API:
  `grunvald91/Mnebyvpn/packages/web/src/telegram-proxy-provisioning.ts`
  and `apps/service/src/dns-mtproxy-bonus-worker.ts` (worker is opt-in).
- Existing DE89 Telemt transport:
  `grunvald91/Mnebyvpn/docs/dns-telegram-proxy-bonus-20261112.md`.
- Nodekit FI bootstrap:
  `nodekit/fleet/fi.json`, `nodekit/service_readiness.py`.

No new nodes or Telegram proxy links are published by this architecture
correction. No active 188/89 network settings are changed.
