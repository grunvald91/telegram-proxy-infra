# MNEBYDNS: stable five-service baseline and measured expansion plan

## Active checkpoint (2026-11-09, 00:53 UTC)

Owner-confirmed Android Private DNS-only working candidates: Gemini, Claude, Grok, X and TikTok. The TikTok user test covered feed/video browsing; other features remain unproven. No promise of universal VPN equivalence.

Live confirmed checkpoint on German node: `/opt/mnebydns-stable-checkpoints/42541741159`. Source renderer retains 132 exact hostnames and 70 dynamic domain families. German SNI proxy binds loopback TCP 15449; public DoT binds 89.125.90.101:853. Nginx, CoreDNS, proxy and Xray auto-start on reboot. Previous temporary rollback timers on RU and DE are inactive.

Confirmed temporary corrections: the Russian Meta/Threads SNI modifications were reverted to the saved RU configuration; synthetic DNS and direct proxy routes for Instagram, Threads and Telegram were removed from the stable output.

**Do not restore the pre-Gemini original snapshot as a default rollback.** A future experiment must revert to the five-service checkpoint using `scripts/mnebydns-stable-five-restore.sh`, with an explicitly registered experimental snapshot; unknown operator changes are fail-closed. New permanent services must preserve the checkpoint's traffic rules.

## Reviewed capacity facts, not load-test results

Current isolated TLS proxy is configured for one Nginx worker with `worker_connections 192`. The systemd unit has `LimitNOFILE=512`, `MemoryMax=100M`, `CPUQuota=20%`, `TasksMax=24`. These limits restrict practical parallelism, but the number of supported customers cannot be inferred from connection settings alone. A proxied client connection consumes sockets on both inbound and outbound sides. The observed node available RAM at 00:53 UTC was 1,222,336 KiB; that is not a customer capacity measurement.

Additional bottlenecks: one public DNS endpoint, one German exit IP, one German SNI backend, origin TLS/SNI dependency, no UDP/443 proxy, DNS-only inability to capture MTProto direct-IP traffic, synthetic replies for Android system names using non-HTTPS ports, no rate limiting or customer-level access controls.

## Pilot observation plan

For several days retain *exactly* the current stable checkpoint. Run non-mutating public DoT checks every six hours (GitHub workflow `mnebydns-stable-five-public-health.yml` on main). The operator separately checks app login, voice/AI queries, feed, uploads, push notifications, time sync and startup after changing mobile networks. Consider a temporary A/B policy for Android FCM/NTP only after capturing baseline results.

For every incident record: Moscow/UTC timestamp, mobile ISP, private DNS setting, target app, action, whether VPN is disabled, DNS response from the server, TCP/443 TLS certificate result on the Russian-to-German path, systemd unit status, and whether an application uses UDP or literal IP. Never capture credentials or message bodies. A passing DNS-only check does not imply app availability.

## Preproduction expansion gates

1. **Operational safety:** test a fail-closed rollback to the five-service checkpoint, simulate a mid-deploy failure, verify file permissions for DynamicUser, healthcheck DoT/853 and SNI/TCP/443 readiness, and monitor after reboot.
2. **Access hardening:** replace root-password automation with an unprivileged deploy identity and scoped sudo actions, verify and pin server SSH host keys from an independently trusted source, rotate old credentials and protect workflows from unreviewed production writes.
3. **Measured load test:** introduce independent generator and observer, increase concurrent connections in controlled steps and measure actual success rate, TCP handshake time, p50/p95/p99 latency, connection resets, egress bandwidth, CPU/memory, file descriptors, Go/CoreDNS CPU, Nginx active connections, socket queues and upstream failures. Do not claim a per-server subscriber limit without a reproducible measurement.
4. **Capacity profile:** only after measurement increase worker connections, file descriptor limits and service cgroup quotas together. Enforce a health-based rollback whenever any service regresses; apply config only during an explicit maintenance window.
5. **Resilience:** add a second independently controlled DoT resolver and foreign egress node, separate health checks for each, managed failover and shared tested routing policy. One synthetic A record to one server cannot provide failover.
6. **Commercialization:** customer provisioning, fair use limits, abuse prevention, payment state, support diagnostics, privacy notice, logs minimized/retention defined, DNS and transport SLA, DDoS controls and cost-per-GB measurement.
7. **Protocol honesty:** label the service DNS+selective SNI proxy, not a full VPN. Telegram native MTProto direct-IP and arbitrary UDP/IP protocols require an actual client-side tunnel or an app-native proxy. Do not route Android FCM/NTP to a TCP/443 proxy as a permanent feature without matching transport support.

## Evidence links

- Stable promotion: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42541741159
- After-promotion system health: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42542578640
- Russian-to-German TLS 8/8: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42542498038
- Public DNS monitoring 14/14: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42543124545
- Confirmed future source hardening regression: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42542854555
