# Telegram WEB proxy pilot on relay89

Status: deployment prepared; read-only preflight passed on 2026-10-01.

## Chosen integration

Host: `cdn.servgo.ru`

Base path: `53wcvyyqhqse3u45`

Upstream implementation:
- repository: `telegramdesktop/tproxy-server`
- pinned commit: `c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8`
- server remains the upstream proof-of-concept implementation

Carrier for the first pilot: `https` (the upstream compatibility baseline).

## Why cdn.servgo.ru

The current foreign server already has:
- public nginx stream TLS/SNI dispatch on TCP 443;
- `cdn.servgo.ru -> 127.0.0.1:4453`;
- a real HTTPS/static site on the local TLS listener;
- a valid certificate;
- no need to alter DNS or take ownership of public 80/443 away from nginx.

The pilot uses upstream base-path Mode B:
- ordinary `cdn.servgo.ru` traffic remains unchanged;
- only `/53wcvyyqhqse3u45/` is forwarded to the WEB relay;
- unauthenticated requests under that prefix are delegated by the relay to a loopback mirror of the same static site.

## Read-only preflight

Successful workflow run: `36864602582`.

Confirmed before deployment:
- Ubuntu 22.04.2 LTS, x86_64
- about 3.0 GB root disk free
- about 1.3 GiB memory available
- ports 2398, 8080, 8081 and 8888 free
- no existing `tproxy-server.service`
- no existing stock `mtproxy.service`
- no existing `tproxy-firewall.service`
- nginx configuration test successful
- `cdn.servgo.ru` resolves to relay89 and returns HTTP 200
- public-site body SHA-256 captured by the preflight

## Deployment layout

```
Telegram WEB-capable client
       |
       | HTTPS 443, SNI cdn.servgo.ru
       v
existing nginx stream dispatcher
       |
       v
127.0.0.1:4453 nginx HTTPS vhost
       |
       | only /53wcvyyqhqse3u45/*
       v
127.0.0.1:8080 tproxy-server
       |
       v
127.0.0.1:2398 stock official MTProxy
       |
       v
Telegram
```

Unauthenticated carrier-prefix requests:

```
tproxy-server
    -> http://127.0.0.1:3000
    -> nginx loopback mirror
    -> /var/www/cdn-servgo
```

## Isolation from legacy proxy stack

The pilot does not replace or reconfigure:
- active Telemt profiles/listeners
- MTG profiles/listeners
- Xray
- WireGuard
- nfqws/zapret rules
- nginx stream SNI routes
- Russian edge server188

It adds separate loopback listeners and one prefix location to the existing cdn.servgo.ru HTTPS vhost.

## Safety

The deployment workflow:
1. verifies the secret is present without printing it;
2. pins the tproxy-server source commit;
3. builds the upstream stock official MTProxy backend;
4. starts the relay/backend before touching the public nginx route;
5. waits for `/readyz`;
6. backs up the current cdn-servgo nginx file;
7. installs the loopback public-site mirror and hidden prefix route;
8. runs `nginx -t` before reload;
9. verifies the public site's body hash is unchanged;
10. verifies an unauthenticated request under the prefix receives the same site body;
11. verifies the backend nftables protection.

A separate manual rollback workflow restores the saved nginx file and stops only the new WEB-proxy services.

## Required GitHub secret

`WEB_PROXY_SECRET`

Format: 32 lowercase hexadecimal characters (16 random bytes), optionally the upstream `dd` form.

Do not commit it to the repository or place it in workflow inputs/logs.

## Workflows

- `WEB Proxy preflight relay89` — read-only checks
- `Deploy WEB Proxy Pilot` — state-changing deployment
- `Rollback WEB Proxy Pilot` — restores nginx and stops pilot services
