# Backup status

Last verified full snapshot: **2026-10-01**

Verified successful workflow run:
- Workflow: `Full Proxy Backup v2`
- Run: `36856965899`
- Backup commit: `824bd931ee5b5ace68a91849943b982ee7dd393a`
- Result: success

## Final snapshot size

- total committed snapshot files: **305**
- total committed snapshot size: **203,376,858 bytes (~203.4 MB)**
- server188: **175 files**, 93,230,173 bytes
- relay89: **128 files**, 110,072,875 bytes
- plus snapshot README and SHA-256 manifest
- Git tree API returned `truncated=false`, so the counted tree is complete

## Source manifest

`legacy-mtproxy/live-snapshot/MANIFEST.sha256.txt` contains **310 source entries**:
- 289 sanitized text/config files saved
- 14 binary executable files saved
- 1 public TLS certificate saved
- 1 private TLS key skipped
- 5 opaque/binary files not committed directly

The two historical `config-and-units.tar.gz` archives are not stored as opaque archives. Their safe regular-file contents are extracted into `archive-extracted/`, then sanitized file-by-file before commit.

Historical `proxy-secret` files found inside an archive are not committed.

## Important binaries preserved

Examples include:
- server188 current `telemt`
- server188 historical Telemt 3.4.10
- server188 custom Caddy binary
- server188 `mtproto-proxy`
- server188 tinyproxy / redsocks
- relay89 current `telemt`
- relay89 historical Telemt 3.4.13
- relay89 `mtg`
- relay89 `nfqws2`
- relay89 Xray

## Preserved configuration/state

The snapshot includes, where present:
- active nginx configuration
- systemd units and drop-ins
- Telemt and MTG configuration
- sanitized WireGuard configuration structure
- sanitized Xray configuration structure
- zapret/nfqws configuration
- redsocks/tinyproxy configuration
- proxy hardening/routing/TSPU scripts
- sysctl tuning
- historical proxy backups and Telemt upgrade work
- sanitized contents recovered from historical tar.gz config bundles
- runtime state: listeners, routes, active services, timers, firewall/rules, Docker state, package inventory and binary hashes
- selected live and historical proxy executables
- public TLS certificate material needed for reconstruction

## Intentionally excluded/redacted

The repository does not intentionally store:
- SSH passwords
- SSH private keys
- TLS private keys
- WireGuard PrivateKey/PresharedKey values
- MTProxy/Telemt/MTG proxy secrets
- API tokens/passwords
- Xray UUID/private credentials
- historical `proxy-secret` files
- other obvious credential values

The backup process sanitizes text/config files and fails closed when obvious unredacted credentials/private-key material are detected.

## Scope

This is a maximum-practical backup of the **Telegram/proxy infrastructure** on the two hosts. It is not a whole-disk backup of unrelated applications, databases, uploaded user files, or every piece of VPS data.

## Running another snapshot

Use:

`Actions -> Full Proxy Backup v2 -> Run workflow`

The workflow is manual-only after stabilization.
