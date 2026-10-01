# Russian server inventory

Status: **initial read-only audit completed 2026-10-01**

## Identity
- Hostname: `artur1.grunvald1991.fvds.ru`
- Public IPv4: `188.120.254.223`
- OS: Ubuntu 24.04.4 LTS
- Kernel: Linux 6.8.0-142-generic
- Architecture: x86-64
- Virtualization: KVM
- Root filesystem: 15 GB, about 63% used at audit time
- RAM: about 956 MiB total
- Swap: about 2.5 GiB

## Confirmed proxy-related listeners

The first audit confirmed a multi-component proxy stack.

### Telegram-related local backends
- `telemt` listening on loopback ports:
  - 127.0.0.1:9443
  - 127.0.0.1:9444
  - 127.0.0.1:9445
- `mtproto-proxy` listening on loopback ports:
  - 127.0.0.1:9460
  - 127.0.0.1:9461
  - 127.0.0.1:9462
  - 127.0.0.1:9463

### Front/proxy layers
- nginx active and listening publicly on:
  - TCP 80
  - TCP 2052
  - TCP 2086
  - at least one public 8443 listener was also present in the audit
- Caddy process is present with a loopback listener on 127.0.0.1:9442.
- tinyproxy is publicly listening on TCP 8888.
- redsocks is active with loopback listeners including:
  - 127.0.0.1:12345
  - 127.0.0.1:12346
  - UDP 127.0.0.1:10053
  - UDP 127.0.0.1:5300
- A Docker-published loopback listener exists on 127.0.0.1:3128.
- A Python service is publicly listening on TCP 8787.

The exact role of every listener still needs a second-stage mapping audit before changes are made.

## Confirmed important files / configuration paths

- `/etc/systemd/system/mtproxy-hardening.service`
- `/etc/sysctl.d/99-telegram-proxy-keepalive.conf`
- `/etc/sysctl.d/99-mtproxy-tuning.conf`
- `/etc/nginx/streams.d/00-mtproxy-relay.conf`
- `/etc/nginx/streams.d/01-mtproxy-stdports.conf`
- `/etc/nginx/streams.d/01-mtproxy-443.conf`
- `/usr/local/sbin/mtproxy-hardening.sh`
- `/root/start-mtproxy.sh`
- `/root/mtproxy-info.txt`
- `/root/mtproxy-relay-links.txt`

Multiple historical backups are also present under `/root/proxy-backups/`, `/root/telemt-upgrades/`, and nginx backup directories. These must not be treated as current configuration until compared against the active files.

## Reverse proxy / TLS
- nginx 1.24.0 (Ubuntu) is active and enabled.
- Caddy process exists, but its exact package/unit ownership and role still need mapping.
- nginx has an active drop-in at `/etc/systemd/system/nginx.service.d/limits.conf`.

## Firewall
The host has UFW/iptables rules. The first audit showed inbound allowances including:
- TCP 80
- TCP 443
- UDP 443
- TCP 22
- TCP 8787
- TCP 8443
- TCP 2052
- TCP 2086
- TCP 8089

A dedicated review is still required to determine which openings are intentional and which belong to the Telegram proxy stack.

## Current interpretation

This server is **not** a single stock MTProxy deployment.

Evidence shows a layered setup involving:
- nginx stream routing
- multiple `telemt` workers/listeners
- multiple `mtproto-proxy` local backends
- Caddy
- tinyproxy
- redsocks
- Docker-based proxying

The exact traffic path must be reconstructed before any migration to Telegram WEB proxy.

## Safety / recovery
No service was restarted, stopped, enabled, disabled, installed, deleted, or modified during the initial audit.

## Secrets
Do not commit proxy secrets, SSH passwords, private keys, real proxy share links, or raw secret-bearing command lines.

## Next audit
Map:
1. active systemd units and ExecStart binaries;
2. nginx stream routes and upstream ports;
3. telemt and mtproto-proxy binary versions;
4. Caddy's exact role;
5. Docker container behind 127.0.0.1:3128;
6. why tinyproxy TCP 8888 is public;
7. current public entry points and which clients use each one;
8. sanitized copies of active configs for Git.
