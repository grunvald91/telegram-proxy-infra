# MNEBYDNS Instagram SNI experiment — isolated SYN-ACK canary

**Status: experimental only. Not deployed on either VPS. Android Instagram E2E not verified.**

## What changed after PR #68 review

The canary **never intercepts production TCP/443**. It creates its own TCP listener on **188.120.254.223:18443**, which merely reads incoming data from one approved public test IP and does not implement TLS or forward traffic. This supports testing whether a specially modified SYN-ACK changes the TCP segmentation of a ClientHello sent with SNI `i.instagram.com`. It does **not** prove the official Android Instagram app can use this port; ordinary Android Private DNS only changes name resolution and will still use port 443.

The packet processor parses only IPv4 TCP SYN-ACK packets from this dedicated port to the selected test IPv4. It rewrites only the advertised TCP receive window (4 bytes) and recalculates the TCP checksum; TCP Window Scale and other TCP/IP headers are preserved. Actual first-client-data length remains a **hypothesis** requiring packet capture.

The queue uses **libnetfilter_queue** directly, explicitly enables kernel `NFQA_CFG_F_FAIL_OPEN` and aborts startup if the kernel rejects the flag. The Bash launcher waits for the queue's verified ready marker and the dedicated listener before inserting any firewall rule. The `--queue-bypass` rule is an additional protection for a missing daemon, **not** a substitute for kernel FAIL_OPEN on queue overflow. See [libnetfilter_queue](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html).

The installer holds an exclusive `flock`, checks for stale tagged rules and pending watchdogs, and **schedules an independent systemd-run timer** before inserting its single `mangle OUTPUT` rule. Normal exit removes the rule; the timer issues the same idempotent deletion after 150 seconds even if the launching shell is killed. A `SIGKILL`, unexpected host shutdown, or external persistence of firewall rules remains an operational risk; verify removal before any follow-up trial. The watchdog command is self-contained and does not require a checked-out Git repository at its firing time.

## Kernel network-namespace integration (10 November 2026)

Implemented in `scripts/tests/integration_mnebydns_synack_netns.sh` and
`scripts/mnebydns_synack_netns_probe.py`. The integration job uses **two
isolated Linux network namespaces** with RFC 5737 test-only addresses,
`192.0.2.1:18443` and `192.0.2.2`, real kernel TCP + native
`libnetfilter_queue`. It never reaches the user's VPS, live DNS, or Meta.
The test generates a genuine local TLS 1.3 ClientHello with SNI
`i.instagram.com`, captures Ethernet packets with tcpdump, and verifies
the TCP checksum on the client side. Network checksum offloads are
explicitly disabled on the test veth interfaces (without that, even the
reference SYN-ACK capture initially appeared to have an invalid checksum).

Reference example, [GitHub Actions run #42864808167](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42864808167):

| Mode | SYN-ACK window | First client data segment | TLS ClientHello TCP segments | Checksum |
| --- | ---: | ---: | ---: | --- |
| Native TCP baseline | 65160 | 1448 bytes | 2 (1448 + 36) | valid |
| NFQUEUE clamped | **4** | **4 bytes** | **20** (4, 212, then many 72-byte segments) | valid |
| Queue handler stopped, `--queue-bypass` | 65160 | 1448 bytes | 2 | valid |

The independent `systemd-run` timer also removed the tagged namespace firewall
rule without the launcher invoking the deletion itself:
`independent_systemd_watchdog=PASS`.

**Interpretation:** a 4-byte first segment and full delivery of ClientHello
are experimentally verified on this Linux test client. The report's assertion
that the remaining ClientHello is transmitted at full-sized MSS without
additional packet overhead is **not validated**: the 1484-byte ClientHello
used 20 TCP data segments instead of 2 on this runner. This must be measured
on actual Android/ISP routes and larger transfers before claiming negligible
performance impact. The test does **not** identify TSPU hardware, demonstrate
censorship evasion, establish Android behavior, or prove that official
Instagram loads.

The integrated CI now fails if kernel NFQUEUE, capture/checksums, on-wire
window clamp, fail-bypass, scoped rule removal or independent systemd rollback
is unavailable. Running the same tests elsewhere requires root/CAP_NET_ADMIN
and a disposable machine with Linux systemd, iproute2, iptables, ethtool,
tcpdump and libnetfilter-queue1. Not suitable as a privileged job on
untrusted contributed PRs.

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
