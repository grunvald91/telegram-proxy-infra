# Two-server audit plan

The audit is intentionally read-only.

## Phase 1 — identify the host

Collect:
- hostname and OS
- kernel and architecture
- public/private network layout
- uptime
- disk and memory usage

## Phase 2 — identify services

Inspect:
- systemd services related to Telegram, proxying, Docker, nginx, Caddy, V2Ray/Xray, MTProxy
- running processes
- Docker containers and compose projects
- listening TCP/UDP ports

## Phase 3 — locate configuration

Find references to:
- mtproxy
- telegram
- proxy
- socks
- v2ray / xray
- nginx / caddy
- Docker compose files
- systemd units

Do not print secret values into chat or commit them to Git.

## Phase 4 — network/firewall

Document:
- public listening ports
- loopback-only ports
- UFW/nftables/iptables rules
- provider firewall rules if known

## Phase 5 — health

Determine:
- which proxy endpoint currently works
- which process owns it
- how it starts after reboot
- where its logs live
- what upstream dependencies it has

## Phase 6 — backup into Git

Copy only:
- sanitized unit files
- sanitized compose/config files
- install/update scripts
- health checks
- architecture notes
- exact package/container versions

Secrets stay outside Git.

## Phase 7 — WEB proxy evaluation

Reference implementation:
- https://github.com/telegramdesktop/tproxy-server

Do not replace the legacy proxy until the WEB proxy is independently deployed and tested.
