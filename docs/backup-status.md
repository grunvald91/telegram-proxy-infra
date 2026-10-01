# Backup status

Last verified full snapshot: **2026-10-01**

Verified successful workflow run:
- Workflow: `Full Proxy Backup v2`
- Run: `36855932204`
- Backup commit: `000300c5f6675a076ae8213eb94c1372232bf792`
- Result: success

## Snapshot size

At the verified commit:
- total snapshot files committed: **253**
- total committed snapshot size: **29,688,822 bytes (~29.7 MB)**
- server188: **145 files**, 272,785 bytes
- relay89: **106 files**, 29,355,974 bytes
- plus snapshot README and SHA-256 manifest

## Saved binaries

relay89:
- `mtg` — 13,455,522 bytes
- `telemt` — 15,439,280 bytes
- `nfqws2` — 321,528 bytes

A later enhancement to the snapshot script also attempts to preserve live/historical executable binaries found inside the whitelisted proxy directories, up to 90 MB per file.

## Manifest

`legacy-mtproxy/live-snapshot/MANIFEST.sha256.txt` records **258 source entries** from the verified run:
- 248 sanitized text/config files saved
- 3 binaries saved
- 5 binary/archive files recorded by SHA-256 but not committed in that run
- 2 sensitive certificate/key files skipped

Files skipped as sensitive in the verified run:
- server188 `/opt/mtproto-canary/tls/fullchain.pem`
- server188 `/opt/mtproto-canary/tls/privkey.pem`

The public certificate can be regenerated/reacquired; the private key is intentionally excluded.

## What is preserved

The snapshot includes, where present:
- active nginx configuration
- systemd service units and drop-ins
- Telemt and MTG configuration
- sanitized WireGuard configuration structure
- sanitized Xray configuration structure
- zapret/nfqws configuration
- redsocks/tinyproxy configuration
- proxy hardening and routing scripts
- sysctl proxy tuning
- historical proxy backups and Telemt upgrade work
- runtime state: listeners, routes, active services, timers, firewall/rules, Docker state, package inventory and binary hashes
- selected proxy executables

## Intentionally excluded/redacted

Do not store in Git:
- SSH passwords
- SSH private keys
- TLS private keys
- WireGuard PrivateKey/PresharedKey values
- MTProxy/Telemt/MTG secrets
- API tokens/passwords
- Xray UUID/private credentials
- other obvious credential values

The backup workflow performs sanitization and fails closed when an obvious unredacted secret is detected.

## Scope

This is a maximum-practical backup of the **Telegram/proxy infrastructure** on the two servers. It is not a whole-disk backup of unrelated applications, databases, user uploads, or all VPS data.
