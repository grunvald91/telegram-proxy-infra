# Foreign server inventory

Status: **initial read-only audit completed 2026-10-01**

## Identity
- Hostname: `First030526`
- Public IPv4: `89.125.90.101`
- OS: Ubuntu 22.04.2 LTS
- Kernel: Linux 5.15.0-73-generic
- Architecture: x86-64
- Virtualization: KVM
- Uptime at audit: about 150 days
- Root filesystem: 15 GB, about 79% used
- RAM: about 1.9 GiB
- Swap: 1 GiB

## Network / public entry points
- WireGuard UDP 51820 is listening publicly.
- nginx listens publicly on TCP 80 and TCP 443.
- SSH listens publicly on TCP 22.
- A `telemt` listener is directly public on TCP 9446.

## Confirmed Telegram/proxy backends

### telemt
Loopback listeners observed:
- 127.0.0.1:9443
- 127.0.0.1:9444
- 127.0.0.1:9445
- 127.0.0.1:9470
- 127.0.0.1:9471
- 127.0.0.1:9472
- 127.0.0.1:9473
- 127.0.0.1:9474
- 127.0.0.1:9475

Associated local stats/admin listeners were observed on ports including 9091, 9092, 9093, 9096 and 9097.

One additional `telemt` process listens publicly on TCP 9446.

### mtg
Five local `mtg` listeners were observed:
- 127.0.0.1:9447
- 127.0.0.1:9448
- 127.0.0.1:9449
- 127.0.0.1:9450
- 127.0.0.1:9451

Active units identify several camouflage/mask profiles:
- `mtg.service` — xapi.ozon.ru mask
- `mtg-avito.service` — www.avito.ru mask
- `mtg-disk-yandex.service` — disk.yandex.ru mask
- `mtg-kinopoisk.service` — www.kinopoisk.ru mask
- `mtg-mail-cloud.service` — cloud.mail.ru mask

### Xray
- `xray.service` is active.
- Xray listens on 127.0.0.1:8443.
- Unit description states VLESS+Reality.

### DPI / routing support
Active units include:
- `telegram-foreign-nfqws.service` — server-side DPI desync
- `telegram-foreign-mss-rules.service` — MSS workaround
- `telegram-rf-media-rules.service` — firewall rules for Telegram RF media ingress

A running `nfqws2` process was observed using:
- `/etc/zapret2/telegram-nfqws.conf`

## nginx / local routing
nginx is active and owns public TCP 443.

Additional local nginx listeners observed:
- 127.0.0.1:5443
- 127.0.0.1:5444
- 127.0.0.1:4453

A focused second-stage inspection is still required to map each public/loopback nginx route to the corresponding telemt/mtg/Xray backend.

## Important files discovered
- `/etc/systemd/system/direct-mtproxy-hardening.service`
- `/usr/local/sbin/direct-mtproxy-hardening.sh`
- `/etc/sysctl.d/99-telegram-proxy-keepalive.conf`
- `/etc/sysctl.d/99-mtproxy-tuning.conf`
- `/etc/zapret2/telegram-nfqws.conf`
- multiple historical nginx and telemt backup files/directories

## Current interpretation

This host is the **foreign Telegram backend / relay side** of the current deployment.

Evidence:
- WireGuard is active on UDP 51820.
- The Russian server's active nginx configuration forwards its Telegram ingress to `10.66.77.1`, explicitly documenting that traffic crosses the WireGuard tunnel to the foreign side.
- This host runs the larger set of Telegram proxy engines (`telemt` and `mtg`), plus nginx dispatching and DPI workarounds.

The foreign server therefore must not be treated as an expendable test machine.

## Safety
No services, firewall rules, packages, or configs were changed during this audit.

## Secrets
Do not commit:
- MTProxy/telemt/mtg secrets
- share links
- SSH credentials
- WireGuard private keys
- Xray private keys / UUIDs
- raw secret-bearing configs

## Next audit
Map:
1. nginx public :443 routing;
2. all telemt unit names -> config files -> ports;
3. all mtg unit names -> ports/masks;
4. WireGuard interface/address relationship to 10.66.77.1;
5. Xray's role versus Telegram proxy traffic;
6. direct port 9446 role;
7. sanitized active configs suitable for repository backup.


## Focused audit details (2026-10-01)

### WireGuard
- Active interface: `tg-relay`
- Address: `10.66.77.1/24`
- Listen port: `51820/udp`
- Peer endpoint observed: `188.120.254.223:35168`
- A recent handshake was present during the audit, confirming that the tunnel is live.

### Active Telemt units
- `telemt-direct-gosuslugi.service` -> `/etc/telemt/direct-gosuslugi.toml`
- `telemt-direct-ozon.service` -> `/etc/telemt/direct-ozon.toml`
- `telemt-direct-sber.service` -> `/etc/telemt/direct-sber.toml`
- `telemt-direct-yandex.service` -> `/etc/telemt/direct-yandex.toml`
- `telemt-rf-media.service` -> `/etc/telemt/rf-media.toml`
- templated `telemt-bandbook@.service` also exists for BandBook-related profiles.

Additional Telemt config files found:
- `/etc/telemt/bandbook-assets.toml`
- `/etc/telemt/bandbook-cdn.toml`
- `/etc/telemt/bandbook-edge.toml`
- `/etc/telemt/bandbook-sberbank.toml`
- `/etc/telemt/bandbook-static.toml`

### Active MTG units
- `mtg.service` -> `/etc/mtg/config.toml`
- `mtg-avito.service` -> `/etc/mtg/avito.toml`
- `mtg-disk-yandex.service` -> `/etc/mtg/disk-yandex.toml`
- `mtg-kinopoisk.service` -> `/etc/mtg/kinopoisk.toml`
- `mtg-mail-cloud.service` -> `/etc/mtg/mail-cloud.toml`

All five were active and running during the focused audit.

### Other active support services
- `direct-mtproxy-hardening.service`
- `telegram-foreign-mss-rules.service`
- `telegram-foreign-nfqws.service`
- `telegram-rf-media-rules.service`
- `xray.service`

### Xray
- Binary: `/opt/xray/xray`
- Config: `/etc/xray/config.json`
- Active/running during the audit.
- The config content itself was intentionally not printed because it can contain sensitive identifiers/keys.

### nginx-hosted auxiliary Telegram web surfaces
The foreign host also serves:
- `tg.servgo.ru` on local TLS port 5443
- `tg.eunoia.fun` on local TLS port 5444
- `cdn.servgo.ru` on local TLS port 4453

These are real HTTPS services sharing the machine with the proxy stack. Any WEB proxy deployment must therefore avoid disrupting existing SNI routing.
