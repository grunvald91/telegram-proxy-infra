# MNEBYDNS Instagram SNI experiment — isolated SYN-ACK canary

**Status: experimental only. Not deployed on either VPS. Android Instagram E2E not verified.**

## What changed after PR #68 review

The canary **never intercepts production TCP/443**. It creates its own TCP listener on **188.120.254.223:18443**, which merely reads incoming data from one approved public test IP and does not implement TLS or forward traffic. This supports testing whether a specially modified SYN-ACK changes the TCP segmentation of a ClientHello sent with SNI `i.instagram.com`. It does **not** prove the official Android Instagram app can use this port; ordinary Android Private DNS only changes name resolution and will still use port 443.

The packet processor parses only IPv4 TCP SYN-ACK packets from this dedicated port to the selected test IPv4. It rewrites only the advertised TCP receive window (4 bytes) and recalculates the TCP checksum; TCP Window Scale and other TCP/IP headers are preserved. Actual first-client-data length remains a **hypothesis** requiring packet capture.

The queue uses **libnetfilter_queue** directly, explicitly enables kernel `NFQA_CFG_F_FAIL_OPEN` and aborts startup if the kernel rejects the flag. The Bash launcher waits for the queue's verified ready marker and the dedicated listener before inserting any firewall rule. The `--queue-bypass` rule is an additional protection for a missing daemon, **not** a substitute for kernel FAIL_OPEN on queue overflow. See [libnetfilter_queue](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html).

The installer holds an exclusive `flock`, checks for stale tagged rules and pending watchdogs, and **schedules an independent systemd-run timer** before inserting its single `mangle OUTPUT` rule. Normal exit removes the rule; the timer issues the same idempotent deletion after 150 seconds even if the launching shell is killed. A `SIGKILL`, unexpected host shutdown, or external persistence of firewall rules remains an operational risk; verify removal before any follow-up trial. The watchdog command is self-contained and does not require a checked-out Git repository at its firing time.

## Prerequisites (read-only inspection first)

- Only operate the designated RU VPS when explicitly approved; **do not deploy to production** on CI success alone
- Linux kernel with `NFQA_CFG_F_FAIL_OPEN`, native `libnetfilter_queue`, `iptables`, `systemd-run`, `flock`, Python 3 and elevated privilege
- Ensure `iptables` backend matches live firewall, and there are no existing rules or listeners for test port 18443, queue 211, or marker `MNEBYDNS_SYNACK_CANARY_211`
- Do not change CoreDNS, working Gemini/Claude/Grok/X/TikTok rules, Nginx maps, WireGuard or the global UDP/443 policy
- Capture only necessary packet headers; monitor live app availability separately

## Offline tests

```sh
python3 -m unittest discover -s scripts/tests -p 'test_mnebydns*.py' -v
bash -n scripts/mnebydns-synack-window-canary.sh
python3 -m py_compile scripts/mnebydns_synack_window_canary.py scripts/mnebydns_synack_listener.py scripts/mnebydns_nfq_failopen.py
```

## Optional two-minute controlled TCP test — not a production fix

```sh
sudo MNEBYDNS_CANARY=YES bash scripts/mnebydns-synack-window-canary.sh TEST_PUBLIC_IPV4
```

From a DIFFERENT test machine (preferably the same mobile ISP path) during the canary window:

```sh
curl -vk --connect-to i.instagram.com:443:188.120.254.223:18443 https://i.instagram.com/
```

The diagnostic TCP listener intentionally does not complete TLS; curl will ultimately time out or report an SSL error. **This is expected.** Capture the SYN-ACK and actual data segment sizes on the RU VPS; verify the presence of a full ClientHello rather than relying on the timing of the curl failure. The simple listener logs only accepted byte counts, never payload. Dedicated port 18443 still needs to be reachable through the provider firewall; do not open the shared 443 port.

### Emergency/manual rollback

```sh
sudo MNEBYDNS_ROLLBACK=YES bash scripts/mnebydns-synack-window-canary.sh TEST_PUBLIC_IPV4
```

Inspect the tagged rules after cleanup and independently after the watchdog deadline; do not infer success from a script exit alone. The timer does not undo external rules created by other operators.

## Acceptance gates

1. Offline tests and CI green.
2. Read-only server inventory: firewall backend, queue availability and test port verified.
3. Independent rollback validated in a disposable network namespace/test host before production.
4. Controlled on-wire SYN-ACK receive window, TCP segment lengths, checksum and subsequent window update captured and reviewed.
5. Only after step 4, design an independently reversible **dedicated ingress** approach for real Android app on TCP/443. This PR does not enable Instagram in DNS.

References: [TCP RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), [window scaling RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html), [kernel checksum offloads](https://docs.kernel.org/networking/checksum-offloads.html), [prior Instagram diagnostic PR #56](https://github.com/grunvald91/telegram-proxy-infra/pull/56).
