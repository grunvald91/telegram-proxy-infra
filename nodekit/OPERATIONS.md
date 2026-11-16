# MNEBYVPN Nodekit: central operations and subscriptions

Status (2026-11-16): offline contract and safety code ONLY. No live monitoring, subscription publishing, or agent executor has been enabled.

## Auto publication and country labels

Newly purchased or provisioned nodes must complete bootstrap, node identity enrollment, verified exit country, real VPN end-to-end, expiration/revocation proof, DNS/TLS, proxy TLS, data-flow and independent external probes. Before a node appears in an existing subscription, the same paid entitlement must be provisioned on that node and its receipt signed with a per-node key; its revision, expiry and VLESS endpoint must match. The controller must preserve current working subscription entries and append eligible nodes with a flag and verified Russian country label (e.g., Germany or Netherlands). Country is derived from real exit evidence rather than the provider name. Existing users keep the same HTTPS /sub/<token> URL and see new nodes upon refresh.

Module control_plane.py contains pure contract functions VerifiedNode, verify_receipt and render_subscription. It is not connected to the live website. The current production Mnebyvpn node adapter and web subscription endpoint still have a hardcoded single server, so automatic multi-node publication is NOT ready until both adapters and the database are upgraded and client tests pass.

## Periodic monitoring and failures

Target cadence is every five minutes, using independent external clients and signed local nodekit service health. monitor_policy.py requires two independent observers with two recent failures each. If local nodekit-owned unit is also down, it identifies a limited local repair candidate. If the process is active but traffic is broken, it classifies data_path_broken and escalates instead of blindly restarting. Multi-server or multi-service failures are always escalated. Collectors, trusted observer identities, timers, external client VPN tests and owner notifications are future integration tasks; adding this source file does not create ongoing monitoring.

## Agent API and permissions

incident_gateway.py accepts bounded signed incident envelopes, rejects stale or tampered input, deduplicates incidents in private SQLite and optionally calls a pinned HTTPS agent API. It passes only structured incident metadata, no passwords, subscription tokens, personal DNS, SSH or VPN secrets, or raw logs. The agent replies only with preapproved action and reason code. It cannot send shell code or change the action classification. Global and unknown events get read-only diagnostics and owner escalation; no global changes, route migrations, bulk revocations, node deletions or spending decisions.

## Scoped automatic recovery

owned_runbook.py accepts a short-lived signed operation permit for one new nodekit-owned systemd unit. It can restart an inactive unit only when explicitly enabled on the node by a protected marker and only once per incident. Shared nginx, Xray, WireGuard, existing 89/188 services, firewall and databases are excluded. A local restart is NOT proof that the end-to-end stream recovered, therefore it must never mark the incident resolved without independent client E2E verification. Current runbook executor has not been deployed or enabled; issuance of signed permits and trusted service identity are future integration work.

## Recovery after serious errors

Every future nodekit deployment should keep verified manifest and hashes of configurations, signed immutable known-good releases, encrypted offsite snapshots of secrets kept outside AI context, a rehearsed restore path, drift detection, a staged canary and limited rollback of the changed service only. Serious architecture changes are proposed to the owner for explicit authorization. Agent may request an evidence bundle containing sanitized metrics, version fingerprints and failure codes but not raw private credentials. A separate recovery controller and offline restore procedure are required when the central controller fails.

## Delivery backlog

1. Node package installers and separate service identities, short-lived access broker and signed enrollment.
2. Multi-node provisioning and subscription endpoint integration in grunvald91/Mnebyvpn, preserving existing profiles and client Karing/INCY behavior.
3. Authenticated probe collectors, a five-minute central scheduler, durable events, agent provider-specific HTTPS integration and Telegram owner reports.
4. Signed controller permit issuance, restricted runbook service deployment, independent verification and rollback.
5. Tested encrypted backups, reproducible topology restore and multi-controller failover.

Reference: docs/mnebydns-safe-config-deployment.md in this repo, and grunvald91/Mnebyvpn/docs/scale-out-contract.md.
