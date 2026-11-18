# AWG 3.1 controller enrollment readiness (read-only)

Fleet phase: `controller-audit` in `.github/workflows/nodekit-fleet-bootstrap.yml`.

The new node's immutable Ed25519 identity is compared to its independently approved SHA-256 in `nodekit/fleet/fi.json`; the root-only controller public Ed25519 SPKI is parsed and its SHA-256 is compared to the independently approved GitHub Actions environment VARIABLE `NODEKIT_CONTROLLER_PUBLIC_SHA256`. This is a public-key fingerprint, not a private key or credential. Without an independent match readiness is FALSE.

The script verifies that the expected reviewed AWG watchdog and IPv4 egress systemd unit files match checked-in source, that all three services remain disabled and stopped, and that the local grant ledger has zero clients. Missing controller public SPKI or unconfigured fingerprint is explicitly reported as a blocker, not silently replaced. It never writes a file, starts a service, changes firewall/DoT or publishes access.

To proceed after audit: deploy a dedicated trusted controller with a root-only Ed25519 signing key, approve its SPKI fingerprint out of band, perform existing `beginNodeEnrollment`/`completeNodeEnrollment` Ed25519 one-time challenge against the current MNEBYVPN PostgreSQL inventory, and install precisely that controller PUBLIC SPKI on the reviewed Nodekit VPS with the independent fingerprint check. Then deploy a separate hardened worker using `awg-trusted-ssh-delivery.ts` and prove signed client grant, expiry and revoke. No signing private key is to be put in GitHub Actions, on the node, or in AI agent context.

Current scope: the FI testing node. Other countries remain off until unique IPAM and identity-reviewed registration.
