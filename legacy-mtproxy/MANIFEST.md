# Legacy deployment manifest

Snapshot date: 2026-10-01

This file records the currently confirmed live components of the two-server Telegram proxy deployment. It intentionally excludes secret values.

## Server 188.120.254.223 — Russian edge

### Public / edge layer
- nginx
- public entry ports include 443, 8443, 2052, 2086, 8089, 993, 995, 465, 853
- WireGuard-forwarded upstream: 10.66.77.1

### Telegram / proxy components
- telemt 3.4.23
- telemt.service
- telemt-yandex.service
- telemt-gosuslugi.service
- mtproxy-hardening.service
- telegram-redsocks.service
- redsocks.service
- tinyproxy.service
- caddy-pq-canary.service
- Docker container: nineseconds/mtg:2

### Important active paths
- /etc/nginx/streams.d/00-mtproxy-relay.conf
- /etc/nginx/streams.d/01-mtproxy-443.conf
- /etc/nginx/streams.d/01-mtproxy-stdports.conf
- /etc/nginx/streams.d/02-user-fastpath.conf
- /etc/systemd/system/mtproxy-hardening.service
- /usr/local/sbin/mtproxy-hardening.sh
- /etc/sysctl.d/99-telegram-proxy-keepalive.conf
- /etc/sysctl.d/99-mtproxy-tuning.conf
- /root/start-mtproxy.sh

## Server 89.125.90.101 — foreign backend

### Tunnel
- interface: tg-relay
- address: 10.66.77.1/24
- UDP listen port: 51820
- peer endpoint observed: 188.120.254.223:35168

### Telemt
Units:
- telemt-direct-gosuslugi.service
- telemt-direct-ozon.service
- telemt-direct-sber.service
- telemt-direct-yandex.service
- telemt-rf-media.service
- telemt-bandbook@.service

Configs:
- /etc/telemt/direct-gosuslugi.toml
- /etc/telemt/direct-ozon.toml
- /etc/telemt/direct-sber.toml
- /etc/telemt/direct-yandex.toml
- /etc/telemt/rf-media.toml
- /etc/telemt/bandbook-assets.toml
- /etc/telemt/bandbook-cdn.toml
- /etc/telemt/bandbook-edge.toml
- /etc/telemt/bandbook-sberbank.toml
- /etc/telemt/bandbook-static.toml

### MTG
- mtg.service -> /etc/mtg/config.toml
- mtg-avito.service -> /etc/mtg/avito.toml
- mtg-disk-yandex.service -> /etc/mtg/disk-yandex.toml
- mtg-kinopoisk.service -> /etc/mtg/kinopoisk.toml
- mtg-mail-cloud.service -> /etc/mtg/mail-cloud.toml

### DPI / hardening
- direct-mtproxy-hardening.service
- telegram-foreign-mss-rules.service
- telegram-foreign-nfqws.service
- telegram-rf-media-rules.service
- /etc/zapret2/telegram-nfqws.conf
- /usr/local/sbin/direct-mtproxy-hardening.sh
- /etc/sysctl.d/99-telegram-proxy-keepalive.conf
- /etc/sysctl.d/99-mtproxy-tuning.conf

### Xray
- xray.service
- /opt/xray/xray
- /etc/xray/config.json

### Auxiliary HTTPS services on same host
- tg.servgo.ru -> local 127.0.0.1:5443
- tg.eunoia.fun -> local 127.0.0.1:5444
- cdn.servgo.ru -> local 127.0.0.1:4453

## Recovery principle

Do not change either live host until:
1. sanitized copies of all active non-secret configs are stored in Git;
2. secret locations are documented;
3. startup/restart commands are documented;
4. a real-client health check exists;
5. the two-host WireGuard path is recoverable.

## WEB proxy rule

Deploy Telegram WEB proxy as a separate test path/hostname first. Do not overwrite the current two-hop deployment in place.
