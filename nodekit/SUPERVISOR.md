# Nodekit VPN: autonomous Xray access supervisor

Status 2026-11-17: implementation and offline contract only. No live VPS,
production subscriber, control-plane connection or service was activated.

The isolated new-VPS daemon is nodekit/vpn_supervisor.py. It only accepts an
existing new-node manifest plus a staged and independently SHA-256-pinned
Xray REALITY binary/config from vpn_stage.py. It never edits shared Xray,
nginx, DNS, WireGuard, iptables or old production VPS.

## Before canary

- On a NEW approved VPS complete preflight, stage, identity, vpn_stage.
- Ensure independently verified Xray binary and restricted no-shell UNIX
  account mnebyvpn-nodekit-xray (dedicated primary group).
- Install the reviewed Python source files under /opt/mnebyvpn-nodekit.
- Place controller-access.spki (44-byte Ed25519 SPKI DER, root:root 0600)
  under /var/lib/mnebyvpn-nodekit/<node_id>. Only the public controller
  key belongs on the node. Do not upload any private identity into CI.
- Review nodekit/systemd/mnebyvpn-nodekit-vpn@.service.example and install
  only with explicit isolated canary approval. Unit is NOT installed by CI.
  Use KillMode=control-group: if supervisor dies, its Xray child must die.
  Starting the daemon manually via SSH is not a production alternative.
- Verify listener ports, system clock/NTP, outbound access, transport,
  country evidence, end-to-end VPN access/revocation and observability.

## Signed commands and strictly local transport

A trusted controller MUST independently authorize each command using live
canonical ACTIVE VPN entitlement, revision and expiry. The included
controller-access.mjs signs a command but DOES NOT authorize billing.

Only a root-only UNIX socket at /run/mnebyvpn-nodekit/<id>/control.sock
accepts requests; no external management HTTP/TCP port is opened.
Each newline-terminated JSON request (max 4096 bytes) contains nodeId,
op (apply or inspect), id (canonical lower-case entitlement UUID),
revision, enabled, expiresAt, issuedAt, nonce and signature.
An inspect request has null revision/enabled/expiresAt. Apply has strict
integer revision 1..1e9, boolean enabled and canonical UTC millisecond
expiresAt (at most 100 days ahead) or null for revoke.

Ed25519 signs the canonical UTF-8 JSON array:
["MNEBYVPN_NODEKIT_ACCESS_V1",nodeId,op,id,revision,enabled,expiresAt,issuedAt,nonce]
issuedAt expires after 45 seconds; nonce is 32 random bytes hex.
The node verifies against pinned controller SPKI via local OpenSSL.
Credentials are never logged. Per-entitlement VLESS UUID is generated
on-node and returned only to a signed local inspect caller.

## Offline hard expiry, revoke and safety

The daemon checks UTC access expiry independently once per second,
without controller availability. A monotonic baseline and persisted UTC
high-watermark refuse startup after >5 s clock rollback. Reliable NTP
is still a release prerequisite. All subscriber records and revisions
are atomically persisted with fsync; older revisions are rejected and
same-revision conflicts are forbidden. Maximum 2500 records.

For a NEW enable the candidate Xray config is checked before switching.
A failed preflight keeps the previous authorized Xray running. For
revoke, reducing expiry, or an expired access, the new state is durable
and the old child is stopped BEFORE risky revalidation. Failure never
restores revoked clients: the supervisor stays fail-closed.
Dedicated Xray child runs as unprivileged mnebyvpn-nodekit-xray using
group-readable temporary runtime config; staged secret config stays
root-only. Root-owned local socket remains mode 0600.

## Not implemented yet

No universal Xray installer, private controller delivery/real enrollment
service, production systemd installation, real E2E from Karing/INCY,
E2E revocation, exit-country proof or live subscription receipt issuing.
No release flag is enabled. Offline tests using signed Ed25519 requests
and mock Xray do not prove live traffic. Do not announce readiness or
sell a new multi-country endpoint based on this PR alone.
