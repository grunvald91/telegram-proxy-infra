# Instagram Android Private DNS — scoped server-side SYN-ACK experiment

**Status:** offline prototype, **NOT deployed**, **NOT proven against Android ISP DPI**.

## Why this is not the report's production configuration

Production MNEBYDNS routes through **CoreDNS**, not Unbound. Do not replace its active DNS configuration, Nginx Stream maps, WireGuard, or general UDP/443 firewall policy. Keep working Gemini/Claude/Grok/X/TikTok routes intact. Existing public DNS tests intentionally confirm that Instagram and Threads have *not* been enabled as production services.

The proposed report's broad `iptables -I INPUT -p udp --dport 443 -j REJECT` can break unrelated traffic, and cannot affect packets already dropped by the ISP. Its global NFQUEUE rule would also affect every customer of the shared port 443. Replacing the SYN-ACK Window Scale TCP option with NOP without updating Linux's TCP state creates a mismatch in negotiated window scale: **we do not do it**.

The experimental daemon changes **only** `Window` in an outbound TCP SYN-ACK belonging to one explicitly allowed test IPv4 and recomputes the TCP checksum. The IPv4 header, TCP options (including Window Scale), and TLS payload are untouched. There is no promise that the client will send 4 bytes first. Linux's next ACK may advertise a larger window, and different Android stacks handle it differently. This is precisely what the on-wire test must measure.

## Offline test

```sh
python3 -m unittest discover -s scripts/tests -p 'test_mnebydns_synack_window_canary.py' -v
bash -n scripts/mnebydns-synack-window-canary.sh
```

## Guarded two-minute on-wire test (NOT production rollout)

1. On RU VPS, identify the **public source IPv4** of a test device from server-side observed metadata. Never put phone identifiers or packet payloads in the repo.
2. Ensure kernel is using `iptables` rules on the actual egress path. Check current mangle OUTPUT/NFQUEUE/port 443 listeners **read-only**. Ensure the test client has a known rollback path and `python3-netfilterqueue` is installed. Do not install from within this canary.
3. From an interactive privileged session on the RU VPS, after ensuring the client is ready to make an HTTPS connection, run:

```sh
sudo MNEBYDNS_CANARY=YES bash scripts/mnebydns-synack-window-canary.sh TEST_CLIENT_PUBLIC_IPV4
```

The script installs a **single client-IP-scoped** SYN-ACK rule with `--queue-bypass`, runs for at most 120 seconds, and removes its rule on exit. No DNS rewrites, upstream changes, cron jobs, services, or Nginx reloads. `--queue-bypass` only bypasses when no queue listener is present; it does **not** replace a rollback plan for a stalled handler. Use a second privileged shell if necessary to remove the tagged rule.

Capture just packet headers during this window, carefully scoped to test public IP, and confirm (a) SYN-ACK `win 4`, (b) the **first actual data segment length**, (c) later ACK window updates, (d) whether the complete ClientHello reaches RU, and (e) whether unrelated 443 traffic and five stable services remain unaffected. Remove packet captures after analysis if not needed.

## Interpretation and next gate

- SYN-ACK `win 4` without subsequent 4-byte ClientHello: **clamp hypothesis not confirmed**. Do not modify production DNS.
- First tiny segment reaches RU but next does not: **consistent with** reassembly/filtering upstream; alone it does not identify TSPU hardware or prove the ISP's exact DPI implementation.
- Both arrive at RU: the tested connection is transport-delivered, **not yet proof the app works**. Check Nginx SNI preread, the RU→DE tunnel and authentic Instagram TLS end-to-end separately.
- Only after a controlled mobile ISP test and app feed/reels/direct tests should a time-limited, host-specific DNS canary be considered. Keep previous working routes unchanged.

## Technical references

- TCP receive-window semantics: https://www.rfc-editor.org/rfc/rfc9293.html
- TCP Window Scale negotiation: https://www.rfc-editor.org/rfc/rfc7323.html
- Geneva server-only evasion research: https://www.cs.umd.edu/~dml/papers/geneva_sigcomm20.pdf
- QUIC Initial encryption visibility: https://www.rfc-editor.org/rfc/rfc9001.html
- Project's diagnostic reference: https://github.com/grunvald91/telegram-proxy-infra/pull/56
