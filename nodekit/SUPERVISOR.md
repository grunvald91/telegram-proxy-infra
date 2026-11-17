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

No universal Xray binary installer, trusted billing-to-command signing
service, production systemd installation, real E2E from Karing/INCY,
E2E revocation, exit-country proof or live subscription receipt issuing.
No release flag is enabled. Offline tests using signed Ed25519 requests
and mock Xray do not prove live traffic. Do not announce readiness or
sell a new multi-country endpoint based on this PR alone.

## NEW VPS workflow: supervisor_install → supervisor_canary

Existing workflow `.github/workflows/nodekit-prepare-new-vps.yml` now offers
two new, explicitly manual choices. `supervisor_install` validates the
staged new VPS, SHA-256 of the pinned Xray binary, and an independent SHA-256
pin of controller Ed25519 SPKI DER; copies strictly trusted scripts, creates
no-login dedicated Xray account if needed, and installs a root-only controller
public key and a fail-closed systemd unit. It runs `systemctl daemon-reload`
but **does not start or enable** the service. It does NOT install Xray itself,
modify existing shared services or publish subscriptions.

`supervisor_canary` additionally starts ONLY this Nodekit service once
with zero subscribers, waits for systemd and its root-only UNIX socket,
and fails/rolls back the new files and attempts to stop its unit if
startup fails. It never runs `systemctl enable`, modifies public firewall
rules or creates user credentials. Re-entry on an already active canary is
refused pending inspection. The canary is NOT a real client E2E result.

The workflow still requires a manually verified **new host**, pinned
`MNEBYVPN_NEW_NODE_KNOWN_HOSTS` and SSH key. It now additionally needs
`MNEBYVPN_CONTROLLER_ACCESS_PUB_SPKI_B64` set to the BASE64 of the 44-byte
Ed25519 controller PUBLIC SPKI DER, **never** its private signing key.
Set input `controller_public_sha256` to the separately verified lowercase
SHA256 of those exact 44 raw bytes and `xray_sha256` to the already pinned
Xray binary hash. Mismatches fail BEFORE any service mutation; an existing
different controller key is immutable and never silently rotated.

`nodekit/forward_command.py` runs only via root SSH and forwards a single
signed command to the local UNIX socket; `nodekit/controller-ssh.mjs` is a
controller-only library with strict known_hosts, a pinned **public** IPv4,
noninteractive SSH and bounded responses. No SSH private key is stored in
Nodekit, web or user-facing subscriptions. This transport alone is NOT
authorization to send commands: the controller must still verify canonical
billing state and independent node enrollment/health before it signs them.

**Pre-pilot blockers:** no fresh VPS host with SSH fingerprint and installed
pinned Xray has been supplied or verified; public controller key may not yet
exist in GitHub Secrets, and the production DB-authorized controller is not
wired to signing/SSH delivery. No real Xray client/expiry/revoke E2E and no
country proof have been performed. The release flag stays off.
