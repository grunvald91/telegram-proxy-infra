# Germany + Finland shared VPN limit: read-only observation gate

**Status:** observation tooling only; no live admission gate. RU188's
`0147_vpn_shared_connection_leases.sql` central transaction ledger is not
proof of data-plane enforcement. It is disabled by default.

An existing purchase can present **MNEBYVPN Германия** and
**MNEBYVPN Финляндия** in a single HTTPS subscription after both profiles
have separate verified grants. The shared limit is fixed by the paid
`order_terms.device_limit`, not multiplied per country.

### What the available protocols can actually prove

- Germany / Xray VLESS: `StatsService.GetStatsOnline` supports an online
  counter, but the configured policy and running API must be checked. The
  documented "online" criterion is network activity in the last 20 seconds;
  an online metric is neither a device identity nor a before-connect gate.
- Finland / AmneziaWG: `awg show awg0 dump` gives peer keys (never printed
  by this script), last handshake timestamps and transfer counters. A recent
  handshake is not an exact "connected" event; no TCP-style close exists.

`shared_vpn_admission_preflight.py --country DE` inspects **only** the
existing Xray config on DE89. It checks whether the local StatsService,
statsUserOnline per client level, uniquely attributed users and API routing
are declared. It cannot prove that the running Xray uses the file.

`shared_vpn_admission_preflight.py --country FI` runs only the pinned local
`awg show awg0 dump` on FI217. Returns an aggregate of configured peers,
recent handshakes, and stale/never-handshaken peers; **these are NOT counted
as sessions**. No peer keys/IPs/usernames/tokens/credentials are logged.
Neither mode edits a live process or database.

The probes ALWAYS return `enforcement_ready: false`. Production remains
blocked until a verified pre-acceptance gate and authenticated per-session
identity exist on BOTH transports, controller responses are bound to pinned
node identity, local expiry/disconnect enforcement is proven, and an
external two-device/two-country race E2E passes. Simply polling online
counts and suspending later is an approximation that permits oversubscription.
An idle AWG peer might be counted as recently active; failover between
countries may keep a place occupied until the grace/lease deadline.

Existing active clients must remain unaffected until that independent
rollout is tested. **Do not enable** `vpn_shared_connection_admission` on
RU188 based on the existence of this observer.

References:
- https://xtls.github.io/en/config/policy.html
- https://github.com/XTLS/Xray-core/blob/main/app/stats/command/command.proto
- https://www.man7.org/linux/man-pages/man8/wg.8.html

Read-only observation fix, 23 Nov 2026: the pinned `amneziawg-tools`
commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` emits **29**
interface columns for `awg show <interface> dump` (AWG 3.1 fields), while
peer rows remain eight columns. A WireGuard four-column parser falsely
reported BLOCKED for FI217 in [live audit 45182487157](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/45182487157).
Reference: https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/show.c
