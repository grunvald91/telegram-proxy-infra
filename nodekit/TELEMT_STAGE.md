# Telemt stage (no public client access)

Nodekit now supports a separate Telegram MTProto/Telemt stage, distinct from the existing Smart DNS SNI candidate.
The official Telemt v3.5.17 release is pinned by GitHub-published SHA-256 digest in telemt_stage.py.
The archive is checked before extracting one ELF binary. No install script is executed.

Stage only: root-only per-node directory, empty users, disabled API, loopback TCP listener candidate,
and an inert systemd unit CANDIDATE (not installed). No clients, no port or firewall modification,
no changes to the existing FI VPN or DE89 Telegram proxy.

Production still requires signed RU188 per-entitlement grants, hard expiry/revoke,
protected control API, external Telegram client E2E and independent controlled release.
Personal DNS still requires wildcard/personal TLS, entitlement checks, DoT E2E and release.
