# Telegram Proxy Infrastructure

Private infrastructure repository for auditing, documenting, backing up, and safely evolving the Telegram proxy deployment across two servers.

## Current goal

1. Audit the existing Russian server without changing it.
2. Audit the existing foreign server without changing it.
3. Identify the actually working Telegram proxy implementation and all files/services it depends on.
4. Copy **sanitized** infrastructure files into this repository.
5. Preserve the current working proxy before any migration.
6. Evaluate Telegram Desktop's WEB proxy proof-of-concept (`telegramdesktop/tproxy-server`).
7. Decide whether to:
   - keep legacy MTProxy and add WEB proxy in parallel, or
   - migrate one deployment to WEB proxy after testing.

## Security rules

Never commit:
- MTProxy secrets
- SSH private keys
- passwords
- API tokens
- real `.env` files
- TLS private keys
- systemd credential contents
- database dumps containing secrets
- raw logs containing credentials or proxy share URLs

Commit only sanitized configs and `.example` files.

## Repository layout

- `docs/` — architecture, audit notes, server inventories, recovery notes
- `legacy-mtproxy/` — sanitized legacy proxy configs and service definitions
- `web-proxy/` — WEB proxy research and future deployment files
- `scripts/` — read-only audit and health-check helpers

## Rule for the audit phase

**Observe first. Do not stop, restart, upgrade, delete, move, or overwrite anything until the current deployment is documented and recoverable.**
