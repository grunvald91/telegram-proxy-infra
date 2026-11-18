# MNEBYVPN Nodekit: AWG 3.1 + Smart DNS/SNI transport + Telegram MTProxy (2026-11-18)

**Scope: new test VPS only.** No production customer, DNS ingress, VPN peer or subscription is enabled by these stages.

## AmneziaWG 3.1 (not ordinary WireGuard)

The previous Nodekit `wireguard-tools` package was standard WireGuard tooling. It is NOT an AmneziaWG installation. The actual AWG stage consists of:

- `amneziawg-go` from official commit `08fe3d33bbb116be09a6183d02609311b8b0c9e8` (2026-11-16), compiled with Go 1.25.
- `awg` and `awg-quick` from `amneziawg-tools` official commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` (v3.1.20260812).
- Build on an isolated GitHub runner; capture SHA-256 for each artifact, transfer via SSH to **only** `217.11.167.91`, refuse conflicting binaries.
- Generate server and header-protection keys locally; create `/var/lib/mnebyvpn-nodekit/<node_id>/amneziawg/awg0.conf` without peers. Port UDP/51821 is reserved for client AWG separately from any planned internal WG tunnel UDP/51820.
- Explicit AWG 3.1 headers, padding, header protection and random trailers. No cookie-disable by default to preserve flood resistance. No NAT, routing, interface activation, firewall edits or user access at staging.

Official docs: https://docs.amnezia.org/documentation/amnezia-wg/ ; https://github.com/amnezia-vpn/amneziawg-go ; https://github.com/amnezia-vpn/amneziawg-tools

The userspace backend is a correctness-compatible first implementation. Its throughput and CPU/latency on the 1-vCPU VPS have NOT been measured, and no customer compatibility claim is made.

## Smart DNS and SNI

`nodekit/dns_proxy_stage.py` creates an isolated root-only candidate for CoreDNS 1.15 and Nginx Stream 1.24.

- CoreDNS TLS service binds **127.0.0.1:8853 only**; Nginx stream routes public TCP/853 only on *approved personal DNS SNI* (initially a single test FQDN).
- DNS exact A-domain overrides (if explicitly configured) return proxy IP, and exact AAAA requests return NODATA; all other DNS queries forward through TLS upstream resolvers.
- Public TCP/443 Nginx prereads SNI and proxies ONLY exact operator-approved names to independently pinned public upstream IPv4 endpoints; default upstream is closed loopback port 9. No default arbitrary CONNECT proxy.
- Until signed domain policy, real per-user FQDN enrollment and a valid CA-trusted TLS certificate are present, both DNS and proxy remain **staged-only**. An empty allowlist is the safe initial policy.

Production activation requires: trusted policy bundle, DNS A/AAAA and wildcard cert validation, identity of each personal DoT hostname, automated expiry/revocation, remote connectivity probes from client networks, TLS and upstream health, and rollback. For blocked SNI (e.g. Meta) DNS routing alone does not change TLS ClientHello and should not be advertised as a working bypass.

CoreDNS docs: https://coredns.io/plugins/template/ ; https://coredns.io/plugins/tls/ ; https://coredns.io/plugins/forward/ . Nginx SNI preread docs: https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html

## Central controller and subscriptions (separate authority)

Existing Nodekit modules `control_plane.py`, `grant-issuer.mjs`, `controller-access.mjs` and PostgreSQL migrations in the **grunvald91/Mnebyvpn** repository define signed enrollment, entitlement-specific grants and opt-in multi-node subscription receipts. They are not a live enrollment daemon or a proven customer access path. New node must remain testing.

Before any public release, controller must prove real IPv4 egress country, AWS/ISP connectivity and E2E per-client activation/revocation, store an atomically consumed enrollment nonce and Ed25519 node observation, and issue the signed VLESS receipt via authenticated billing-connected writer. The existing /sub/<token> should be extended, never replaced. AWG and Smart DNS require separate product-specific credentials; VLESS receipt format cannot represent AWG client profiles.

## Test sequencing

1. Existing `prepare_all` installs CoreDNS, Xray, Nginx, wireguard-tools and builds empty Xray stage.
2. `nodekit-amneziawg-stage.yml` manually builds official pinned AWG and stages zero-peer `awg0.conf` on the approved new VPS.
3. `nodekit-prepare-new-vps.yml` with `mode=dns_proxy_stage` stages closed-by-default resolver and proxy candidates.
4. A separate explicitly approved promotion workflow must later check public DNS/certificate, identity, controller, service startup and E2E. There is **no promotion of these candidates in this PR**.

TOFU SSH host-key trust and a shared password remain acceptable only for the single isolated test VPS. Future automatic scale-out needs independently pinned SSH fingerprints, per-VPS scoped secrets, signed controller-issued deployment plans, budget authorizations and owner-approved irreversible actions.


## Customer proxy is Telegram MTProxy, not DNS SNI

The Nginx SNI route here is **only Smart DNS's internal transport**, not
Telegram MTProxy. The user-facing proxy product means **Telemt MTProto**,
with the existing control and user lifecycle on controller RU188 and existing
Telemt DE89. FI Telemt is not staged or tested and must fail closed. See
[CONTROLLER188_TELEGRAM_PROXY.md](CONTROLLER188_TELEGRAM_PROXY.md). The
existing central authority is RU188; do not create a second controller.
