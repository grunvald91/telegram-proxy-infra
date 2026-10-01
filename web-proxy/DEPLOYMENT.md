# WEB proxy pilot deployment

Target host: relay89 (`89.125.90.101`)

Public hostname: `cdn.servgo.ru`

Upstream server implementation:
- repository: `telegramdesktop/tproxy-server`
- pinned commit: `c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8`
- upstream status at deployment planning time: proof-of-concept WEB proxy server

## Deployment mode

Mode B from upstream `BASE_PATH.md`:
- the existing production site remains served directly by nginx;
- one randomly generated hidden base path is proxied to `tproxy-server`;
- unauthenticated traffic under that prefix is delegated to a loopback mirror of the same site;
- the existing SNI router, WireGuard relay, Telemt/MTG/Xray deployment and other Telegram paths are not modified.

## Ports

- 127.0.0.1:8080 — tproxy-server
- 127.0.0.1:8081 — tproxy admin
- 2398/tcp — official MTProxy client backend, protected from non-loopback traffic by upstream nftables unit
- 8888/tcp — official MTProxy stats, protected from non-loopback traffic by upstream nftables unit
- 127.0.0.1:3000 — nginx mirror of the existing cdn.servgo.ru static site

## Secrets

The WEB proxy secret and base path are generated on relay89 during deployment.
They are not committed to Git and are not printed into Actions logs.

A root-only client file is created on the server and copied by the deployment
workflow into a private GitHub Actions artifact.

## Rollback

Before editing nginx the deploy script copies the active nginx files and runtime
inventory to `/root/tproxy-predeploy-<timestamp>/`.

Any deployment failure before the final success marker:
- stops/disables only the new tproxy/official-MTProxy units;
- restores the original cdn.servgo.ru nginx site;
- removes/restores the tproxy nginx include;
- validates and reloads nginx;
- leaves all legacy Telemt/MTG/WireGuard/Xray services untouched.
