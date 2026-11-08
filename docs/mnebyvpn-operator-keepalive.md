# Operator VPN keepalive — scope and deployment guard (2026-11-08)

One operator-owned existing **trial** entitlement, selected by the SHA-256 of its current opaque subscription token. No new subscription URL or client UUID is minted. No VPN customer's trial/payment ledger is altered.

- Code: `scripts/mnebyvpn-owner-keepalive.py`, intended to run on control-plane VPS 188 under root in the existing private WireGuard network.
- Installer: `scripts/mnebyvpn-owner-keepalive-install.sh`, creates dedicated systemd oneshot/timer on that host only.
- On initial activation, requires **exactly one ACTIVE, unexpired internal_trial** whose link matches the hashed target, with no paid credits or renewal orders. Persists a specific `vpn_operator_test_grants` row.
- Before every renewal, requires live foreign node, local VPN worker and website health checks.
- When less than 45 days remain, extends only that entitlement to 75 days from current DB time and increments its revision; existing signed VPN worker applies it to the node. This stays within the node's 100-day upper bound.
- After application, signed node INSPECT must report the same revision, relative TTL within 90 seconds of DB, and **the same credential SHA-256** as before.
- Timer runs daily and every 12 hours after its previous run. After reboot, catches up. It does not depend on GitHub schedule.
- If the link is revoked, grant is revoked, provider/ledger scope changes, node is unhealthy, or existing credential changes: **fail closed**; never replace key or silently mint a new access.
- Activation changes the entitlement expiry only, not `trial_grants.access_expires_at` or payment history. Any later paid renewal must reconcile the operator grant and original trial ledger explicitly.
- Extending the entitlement causes the Xray node agent to reconfigure its isolated child and briefly interrupt current sessions on that node. This is an acknowledged tradeoff, limited to once per roughly 30 days when the service remains healthy.
- Private signed keys, UUID and raw subscription bearer URL must **not** appear in CI logs. Only the irreversible token hash is committed.

**Status:** scripts committed to a feature branch for review. Server-side installation and extension require an allowed, verified production execution channel. Do not claim permanent access until both the operator timer and signed-node expiry readback have been verified.
