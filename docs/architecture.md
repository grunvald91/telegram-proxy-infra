# Current proxy architecture

Status: reconstructed from read-only audits on 2026-10-01.

## High-level topology

```
Telegram client
      |
      | public TCP 443 / 8443 / 2052 / 2086 / 8089
      | and several standard TLS-like ports
      v
Russian edge
188.120.254.223
nginx stream dispatcher
      |
      | WireGuard tunnel
      | destination seen in active config: 10.66.77.1
      v
Foreign relay/backend
89.125.90.101
nginx + telemt + mtg + DPI routing helpers
      |
      v
Telegram
```

## Russian edge role

The active nginx stream config on server 188 explicitly states that phones connect to the Russian edge and nginx forwards the encrypted bytes through WireGuard to the foreign server.

Confirmed examples:
- public 8443 -> 10.66.77.1:443
- public 2052 -> 10.66.77.1:443
- public 2086 -> 10.66.77.1:443
- public 8089 -> 10.66.77.1:443
- public 443:
  - selected real website SNI values (BandBook) -> local HTTPS
  - default -> 10.66.77.1:443
- selected fast path -> 10.66.77.1:9470

The edge preserves TLS/FakeTLS bytes rather than terminating the Telegram proxy flow.

## Foreign backend role

Server 89 exposes nginx on public 443 and runs multiple local Telegram proxy backends.

Observed families:
- telemt
- mtg
- Xray/VLESS+Reality
- nfqws/zapret2 DPI desync helpers

The server also owns the public WireGuard listener on UDP 51820.

## Russian edge active Telegram services

- telemt 3.4.23
- telemt.service
- telemt-yandex.service
- telemt-gosuslugi.service
- nginx
- mtproxy-hardening.service
- telegram-redsocks.service
- redsocks.service
- tinyproxy.service
- caddy-pq-canary.service
- Docker container `mtproto-proxy` using image `nineseconds/mtg:2`, bound to loopback 127.0.0.1:3128

The Caddy canary is a custom binary at `/opt/caddy-pq/caddy` using `/opt/mtproto-canary/Caddyfile`; it is not a stock system Caddy installation.

## Foreign backend active Telegram services

- multiple telemt instances/listeners
- five mtg mask profiles
- nginx
- telegram-foreign-nfqws.service
- telegram-foreign-mss-rules.service
- telegram-rf-media-rules.service
- Xray VLESS+Reality
- WireGuard

## Important implication for WEB proxy migration

The current deployment provides:
- Russian ingress;
- encrypted forwarding through a tunnel;
- multiple fallback/public ports;
- multiple camouflage profiles;
- DPI-specific handling;
- coexistence with real HTTPS services.

Telegram Desktop's new `tproxy-server` WEB proxy proof-of-concept has a different reference architecture built around HTTPS/WebView transport plus a local official MTProxy backend.

Therefore WEB proxy should initially be deployed **in parallel under a separate hostname/profile**, not used as an in-place replacement for the existing two-hop system.

## Migration rule

1. Snapshot sanitized active configuration from both hosts.
2. Record recovery/startup procedures.
3. Verify the legacy proxy from a real client.
4. Build an isolated WEB proxy instance.
5. Test Desktop and Android client compatibility.
6. Compare reliability under the networks that motivated the current two-hop/DPI setup.
7. Only then decide whether any legacy path can be retired.
