# Review of Telegram fastpath repair — 2026-11-12

## Scope and exact live fix

The original RU `/etc/nginx/streams.d/02-user-fastpath.conf` directed the `:10443` listener to `10.66.77.1:9470`. Foreign Telemt `:9470` is loopback-only (`127.0.0.1:9470`), hence that WG destination failed with connection refusals/timeouts. A guarded live repair changed only the RU line to `proxy_pass 10.66.77.1:443;`; the DE Nginx `:443` SNI dispatcher maps `media.bandbook.site` to `127.0.0.1:9470`.

**This is a targeted live repair; it is not proof that all Telegram users are stable or that public TCP/443 is available from every network.**

Live apply with preflight, one-line replacement, saved on-server backup, `nginx -t`, graceful reload, and local/WG TCP postchecks:
https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43229909069

## Second code and live review

- Read-only check #1: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43230776594
- Read-only check #2 including regular :443 path: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43231228730
- RU active fastpath config contains new WG target exactly once and no old `:9470` target, `nginx -T` includes that active route and listener :10443.
- Foreign active `nginx -T` contains exactly one `media.bandbook.site -> 127.0.0.1:9470` map and `ssl_preread on;`.
- Sending **unauthed synthetic TLS ClientHello** with SNI `media.bandbook.site` through RU local :10443 produced a newly observed established TCP connection on DE loopback :9470 (no new connection to :9443). The same synthetic experiment through normal RU local :443 also produced a DE :9470 connection. This is bounded route evidence, not authenticated Telegram media/session E2E.
- Active `iptables-save -t nat`, `iptables-save -t mangle`, and `nft list ruleset` on RU contained **zero** matches for port 10443. We therefore have **no evidence that the special subnet redirect into :10443 remains active**. Do not claim the special fastpath currently serves clients. Default public RU :443 forwards over WG :443 and its SNI path was separately proven with synthetic ClientHello.
- `iptables` and `nft` rules explicitly mentioning `dport 443` contained no DROP/REJECT entries in the sampled rules, but this does **not** exclude chain-wide policies, nonmatching drops, provider filtering, client ISP filtering, or dynamic rules.
- Public RU :443 was unreachable with two timeouts from one GitHub runner, while it was accessible from the DE host; RU public :8443, 2052, 2086 and 8089 were reachable from the runner. The cause and scope of client-region-dependent TCP/443 reachability is still **unverified**.
- No production nftables, iptables, WireGuard, DNS, SmartDNS, VPN, DE Nginx, or foreign Telemt settings were changed during review.

## Code review findings and corrections

1. **Original repair's TCP-only health proof was insufficient.** Added read-only synthetic SNI evidence on two entry points, distinguishing route validation from actual Telegram sign-in or real mobile traffic.
2. **RU :10443 special redirect was presumed active without verification.** Observed no matching active rules; do not re-enable special-subnet redirect without independent need and scoped validation. The normal :443 path already routes this SNI to :9470.
3. **Applied server config wasn't recorded in repository desired state.** Added sanitized `ops/telegram-fastpath/02-user-fastpath.expected.conf`; immutable `legacy-mtproxy/live-snapshot` remains historical and unchanged. This expected file is a reference for the route and is not claimed to be a byte-for-byte copy of the entire live file or an automatic deployment source.
4. **Interrupted remote execution had a signal handling gap and backups could inherit readable file permissions.** Repair script now preserves restricted backup mode (0600), applies umask 077, handles SIGINT/SIGTERM through EXIT rollback, and explicitly reports restore-copy failures. These changes are for future runs and do not require additional production writes.
5. **Backout caveat:** an immediate process SIGKILL or host power failure cannot trigger shell EXIT, nor can the script reverse pre-existing routing/firewall restrictions. Backup remains available on RU for manual recovery.

## Remaining operational gate

From a real Telegram client on affected cellular and Wi-Fi networks, verify connection stability, media transfer and observed route/port; correlate brief Telemt journal error categories and Nginx connection counters at the same time. Avoid treating arbitrary `upstream` or `timeout` mentions as proven Telegram user failures.

The proxy may still be unstable on some ISPs, especially on public :443. The source of that intermittency cannot be established from these two runner/server network vantage points alone.

## Actions cost

This second-review turn used two new targeted **read-only** workflow runs (IDs 43230776594 and 43231228730), both successful. Actual billable minutes were not retrieved; do not infer them from runtime.
