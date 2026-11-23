# Reviewed one-shot deployment actions

An added, immutable `nodekit/fleet-operations/<cc>-telemt-stage-YYYYMMDD.json`
can request **only** the already reviewed `telemt-stage` dormant
stage of the existing fleet bootstrap workflow. The source target must match
the exact approved immutable `nodekit/fleet/<cc>.json` inventory identity.
The operation schema rejects unknown fields and any subscriber publication.

The fleet workflow selects only files **added** in a main-branch push
(diff-filter=A); edits to an old action cannot re-trigger deployment.
A normal fleet inventory addition still uses `auto`, and no operation
ever triggers a VPN reinstallation by mistake.

The included FI one-shot action stages only a verified dormant Telemt candidate.
**No live Telegram client, public port, systemd unit or entitlement is activated.**
This is not completed production DNS/Telegram deployment; the signed
controller grant and E2E release remain missing.
