# Second WEB proxy via Russian edge and WireGuard

Status: **deployed and end-to-end verified 2026-10-01**

## Purpose

This is a second, independent Telegram WEB proxy path. Unlike the first
`cdn.servgo.ru` pilot, the public client connection terminates on the Russian
server first and then crosses the existing WireGuard tunnel to the foreign server.

## Public path

```
Telegram WEB-capable client
        |
        | HTTPS :443, SNI bandbook.site
        v
188.120.254.223 (Russian edge)
        |
        | nginx TLS site: bandbook.site
        | hidden Mode-B base path only
        v
10.66.77.1:8082 over WireGuard tg-relay
        |
        v
89.125.90.101 (foreign relay)
        |
        | nginx WG-only bridge
        v
127.0.0.1:8084 tproxy-server-ru
        |
        v
127.0.0.1:2399 mtproxy-ru
        |
        v
Telegram
```

## Decoy/public-site path

Unauthenticated requests under the hidden prefix are delegated through a loopback
upstream on the foreign server:

```
tproxy-server-ru
 -> 127.0.0.1:3002 nginx
 -> WireGuard
 -> 10.66.77.2:3001 nginx on Russian edge
 -> /var/www/bandbook
```

This keeps `tproxy-server`'s `public_upstream` loopback-only as required by the
upstream implementation while still making decoy responses come from the same
BandBook site.

## Ports

Russian edge:
- public TCP 443: existing nginx stream/SNI dispatcher
- local TLS BandBook: 127.0.0.1:8444
- WG-only BandBook mirror: 10.66.77.2:3001

Foreign relay:
- WG-facing nginx bridge: 10.66.77.1:8082
- relay: 127.0.0.1:8084
- relay admin: 127.0.0.1:8085
- loopback decoy bridge: 127.0.0.1:3002
- second official MTProxy: TCP 2399
- second official MTProxy stats: TCP 8889

## Services

Russian edge:
- `tproxy-web-ru-edge-firewall.service`
- existing nginx
- existing `tg-relay` WireGuard

Foreign relay:
- `tproxy-server-ru.service`
- `mtproxy-ru.service`
- `tproxy-firewall-ru.service`
- existing nginx
- existing `tg-relay` WireGuard

## Firewall

The Russian mirror port 3001 is allowed only from the foreign WireGuard peer
`10.66.77.1` through interface `tg-relay`.

Foreign MTProxy ports 2399 and 8889 are blocked on non-loopback interfaces by
`tproxy-firewall-ru.service`.

## Verification

Successful workflow:
- `Verify and Export RU WEB Proxy`
- run: `36870059072`

Confirmed:
- second relay service active;
- second official MTProxy active;
- backend firewall active;
- relay `/readyz` healthy;
- expected listeners active;
- no excessive recent MTProxy middle-end disconnects;
- BandBook mirror reachable through WireGuard;
- invalid hidden-prefix path matches the public-site response class;
- a correctly derived WEB bridge capability returns HTTP 200 through the full
  188 -> WireGuard -> 89 chain.

## Backup

Post-deployment sanitized full snapshot:
- commit: `ca162ee5c93ddf78d85512d4b9ac6b56555127af`
- total snapshot: 332 files, 227,075,841 bytes
- server188: 179 files
- relay89: 151 files
- tree API: complete (`truncated=false`)

Second-path profile secrets and MTProxy secrets are redacted in Git. The token key
is hash-recorded but not committed.
