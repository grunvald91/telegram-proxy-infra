# MNEBYDNS — prelaunch code review for ChatGPT / Instagram / Threads

Date: 2026-11-09 (UTC). Branch: `diagnostics/mnebydns-meta-ingress-matrix-20261109`.

## Verdict

**Source-level and read-only preflight checks PASSED. No public three-app canary was launched by this review.** The combined production cutover and the Android no-VPN app acceptance are still unverified; do not promote permanently.

## Agreed routing

- ChatGPT/OpenAI HTTPS TLS passthrough: Android Private DNS on DE `89.125.90.101:853` → DE public SNI TCP/443 → German backend `127.0.0.1:15449`. Same route class as Claude/Google, not through RU.
- Instagram/Threads: selected DNS names → RU public `188.120.254.223:443` → private WireGuard `10.66.77.1:19443` → DE Meta SNI TLS passthrough.
- All five previously working services remain in baseline; Telegram is not added. QUIC/direct-IP and voice UDP are not validated by this TCP/443 design.

## Confirmed review findings and corrections

1. **German backend hard restart risk.** Combined activate and rollback initially restarted `mnebydns-googlepilot.service`, potentially disconnecting established stable-service sockets. Corrected to `nginx -t -c` followed by systemd `HUP` to the Nginx master for a graceful configuration reload. Real in-service HUP behavior is not yet exercise-tested in this new canary.
2. **DNS rollback readiness gap.** The rollback checked the DNS service active but did not require a confirmed listener on public DoT port 853. It now checks a `dns_ready` gate and refuses to report success otherwise.
3. **Checkpoint identity drift.** Stage now records `checkpoint.ref` and includes it in a SHA-256 staged-file manifest. Activation and rollback verify the same active checkpoint path; any changed owner revision fails closed.
4. **Watchdog readiness.** Stage and activation require an independently active persistent systemd rollback timer, with a shared time-bound deadline. The timer is installed before live DNS cutover.
5. **Combined route overlap.** The renderer validates that Meta routes do not enter the German ChatGPT upstream, ChatGPT routes do not enter the Russian Meta sidecar, and neither enters Telegram.
6. **NGINX configuration grammar.** All three generated Nginx configurations were syntax-tested in GitHub Actions using an isolated runtime directory, with origin TLS passthrough rather than HTTPS interception.

## Evidence

- Offline multi-app safe-renderer, shellcheck, watchdog, and Nginx syntax checks: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42552074777
- Read-only live preflight of DE stable checkpoint, DNS/853, German proxy/15449, service units and original RU SNI/WG route: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42552120373
- The earlier faulty combined RU-ChatGPT rollout auto-rolled back independently on both servers: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42549813349

The offline run proved the sample-rendered configs and scripts work as written; the read-only live run proved the current stable five-service checkpoint is present. Neither proves that the new combined pipeline works on a real Android app.

## Remaining release gates

- A **single explicitly authorized time-limited three-app canary**, not a permanent promotion; orchestrate RU and DE under the same deadline, with each server's independently armed watchdog.
- Validate ChatGPT A DNS → DE, Meta A DNS → RU, the pre-existing five A DNS routes → DE, TLS certificates end-to-end on both paths, and no accidental Telegram rewrite. Handle transient DNS upstream lookup failures separately from routing-regression assertions, preserving fail-safe rollback.
- Test ChatGPT, Instagram and Threads on Android with the VPN OFF. A functioning TLS handshake and DNS rewrite alone do not establish that the applications operate correctly.
- On any failure or timer expiry, verify exact restoration of the five-service checkpoint on DE and original nginx 443 mapping on RU. Only then consider a permanent service upgrade.
- For any production promotion, separately test quota/auth, ECH/QUIC/UDP, DNS RR consistency and device network changes.

**Release status: OFFLINE REVIEW PASSED; LIVE THREE-APP ACCEPTANCE PENDING.**
