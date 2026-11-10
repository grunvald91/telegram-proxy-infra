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

## External public readiness measurements — 10 November 2026

An actual GitHub-hosted runner was used as the source of the test,
with **no SSH, no server-side changes, no app traffic and no mobile operator**.
See [Actions #42868024325](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42868024325).

| TCP target | From GitHub runner |
| --- | --- |
| RU 188.120.254.223:22 | Connected, 189 ms |
| RU 188.120.254.223:80 | Connected, 187 ms |
| RU 188.120.254.223:443 | TCP timeout after 4004 ms |
| RU 188.120.254.223:18443 | TCP timeout after 4004 ms |
| DE 89.125.90.101:443 | TCP timeout after 4004 ms |
| DE 89.125.90.101:853 | Connected, 148 ms |

The DoT server `dns.mnebyvpn.site:853` passed TLS certificate
verification and replied with NOERROR to each A query. Both
`i.instagram.com`, `graph.instagram.com` and `www.threads.com`
resolved to addresses that were **neither** RU nor DE; the existing
Instagram/Threads canary remains disabled in public DNS. Working
`gemini.google.com` and `claude.ai` queries returned DE as before.

**Conclusions restricted to this vantage point:** both RU ports 443 and
18443 were not TCP-connectable from this runner within four seconds,
whereas RU ports 22/80 were. DE port 443 also timed out from the same
runner, while DE 853 responded. This does **not** identify whether a
host firewall, provider routing, anti-abuse filtering or an intermediate
middlebox caused the timeouts. No operator TSPU inference is possible
from this external probe, and no actual Android Instagram end-to-end
connection was attempted. An additional read-only RU firewall/listener
inventory is necessary before the next live canary.

## RU server synchronized field diagnostic — 10 November 2026

This is **actual RU VPS evidence**, not the earlier isolated Linux simulation.
Authorized pinned-SSH read-only workflows were executed on
`188.120.254.223` while an external GitHub runner connected to ports
80, 443 and 18443. No Android client was used.

- [Read-only RU inventory #42870142342](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42870142342):
  `nginx` owns TCP/80, TCP/443 and TCP/853; TCP/18443 is free; UFW is active
  and INPUT default is DROP; a test-specific native libnetfilter_queue
  library is not installed; NFQUEUE 211 is unclaimed; systemd available.
- [Synchronized SYN path #42871212161](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42871212161):
  80 received 3 SYN and emitted 3 SYN-ACK; 443 received 7 SYN and emitted
  **zero observed SYN-ACK** to the runner; 18443 received 9 SYN with no
  SYN-ACK (no listener/no allow rule).
  This rules out an upstream drop of the **initial TCP SYN** on this
  specific Github→RU path; it does not prove later TLS behavior.
- [Netfilter count audit #42871748605](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42871748605):
  UFW rules for destination port 443 were hit during the test window,
  though rule counters aggregate all sources. This is not definitive
  per-flow proof of an ACCEPT verdict.
- [Return route #42872733656](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42872733656):
  return route uses `ens3` and source 188.120.254.223, not WireGuard.
  The kernel reported one `SYN-RECV` entry for the test runner on 443.
  `tcp_fwmark_accept=0`; no listener queue overflow was observed.
- [Nftables postrouting #42873356523](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42873356523) and
  [NFQUEUE worker audit #42873643156](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42873643156):
  `inet telegram_nfqws` contains a `postrouting` rule for
  `tcp sport 443` with a mark condition and NFQUEUE with bypass.
  The active NFQUEUE is **210**, used by an active
  `telegram-nfqws.service`; queue depth and kernel/user queue overflow
  drop counters were zero at the snapshot. This rule **might** interfere
  with outgoing SYN-ACK when its mark condition matches, but queue
  presence and empty drop counters do not prove whether nfqws itself
  drops or modifies the SYN-ACK. Do not disable or alter the existing
  Telegram worker without a separate isolated controlled comparison.

**Decision gate:** The initial connectivity issue on the GitHub→RU route
is *before TLS ClientHello*. It must not be attributed to Instagram SNI
or TSPU. A temporary test-only TCP/18443 listener and per-source INPUT
allow experiment was prepared, with 70-second independent timer rollback,
but the new GitHub Actions job that would remotely change firewall rules
was blocked by tooling security controls. No remote modifications were
carried out. Review that canary script separately in the repo and use an
explicitly authorized operator session for any active trial. Do not
change the existing working public HTTPS/443, DNS, nginx, or Telegram
nfqws chain as part of this diagnostic PR. Android mobile testing is
still pending.

## Owner-approved A/B experiment — queue 210 SYN-ACK bypass

The active RU service `telegram-nfqws.service` uses `inet telegram_nfqws`,
base chain `post` (hook `postrouting`, policy `accept`). A rule selecting
`tcp sport 443` by packet mark sends packets to NFQUEUE 210 (bypass enabled).
The prior synchronized tests showed GitHub runner SYN to RU/443 **arrives**
but no corresponding SYN-ACK was observed on the outgoing interface.
The rule may be involved; **the causal mechanism is not confirmed**.

**This A/B test has not been executed on the live RU server yet.** Prior
attempts to create GitHub Actions workflows that would remotely change firewall
configuration were blocked by tool safety controls. We do not circumvent
those controls or commit credentials. The authorized owner can instead run
the following from an already SSH-authorized Codespace in the repository:

```bash
git fetch origin experiment/instagram-synack-window-canary-20261110 &&
git switch --detach FETCH_HEAD &&
bash scripts/mnebydns_ig_queue210_codespace_ab.sh
```

The script automatically identifies the Codespace's actual public IPv4 as
seen by the RU SSH server, probes RU TCP/443 three times as a baseline, and
aborts if the baseline already connects successfully.

It then uses the **same authenticated SSH channel** to perform a bounded
trial. The remote agent:

1. Requires an `inet telegram_nfqws post` base chain with
   `hook postrouting`, `policy accept`, and exactly one marked NFQUEUE
   210 queue-bypass rule matching `tcp sport 443`
2. Verifies the exact nft syntax with `nft --check -f -`
3. Creates a unique rollback helper under root-owned `/run`, and arms
   a **95-second independent systemd timer BEFORE** inserting any rule
4. Inserts exactly one rule ahead of the queue:
   `ip saddr RU ip daddr TEST_CLIENT tcp sport 443
   tcp flags & (syn | ack) == (syn | ack)
   counter return comment "MNEBY_IG_SYNACK_AB_<RUN_ID>"`
5. Allows connections for **55 seconds**, records only the rule packet
   counter, deletes that exact tagged rule using its nft handle on normal
   exit, and verifies it is absent. The independent timer is also able to
   remove the tagged rule if the interactive session disappears.

There is **no change to DNS, Nginx, the Telegram worker, the live NFQUEUE
210 rule, generic TCP/443 accept policy, or other clients**. The external
peer sees the pre-test baseline, three connection attempts during the
brief bypass, and a post-rollback reference.

Decision criteria:
- Baseline TIMEOUT and bypass CONNECTED (and a nonzero tagged rule
  counter): evidence that handling by the current `post` queue rule may
  be involved. Preserve logs, do not roll out globally; check that normal
  network services still work
- Baseline TIMEOUT and bypass TIMEOUT: no evidence that bypassing this
  specific chain fixes ingress; investigate another netfilter chain,
  host stack, provider output filtering, and kernel SYN path
- Baseline CONNECTED: no experiment performed, since the failure is
  not reproduced on the Codespace→RU path
- Missing watchdog activation or unexpected chain structure: script
  aborts without adding the rule

The command runs from the **Codespace**, not the official Instagram
Android app, and provides transport-layer evidence only. Real mobile
operator testing is still a separate gate. Independent kernel namespace
and unit tests are in `scripts/tests/integration_mnebydns_ig_queue210_ab_netns.sh`
and `scripts/tests/test_mnebydns_instagram_queue210_ab.py`.

## Stage 3: read-only inspection of actual RU VPS

Added `scripts/mnebydns_instagram_ru_readonly_preflight.py`. This script
does **not** install anything, touch public TCP/443, alter DNS, start a
listener, open firewall ports, or capture user traffic. It prints a bounded,
non-sensitive summary of port ownership, queue 211, existing canary rules,
iptables backend, nftables and systemd capabilities. The script and its
mocked unit tests are validated by PR CI.

**Remote execution has not been performed or authenticated in this stage.**
A new CI workflow that would inject the RU SSH password was not permitted,
so no credentials are copied into a new workflow or written to the
repository. A trusted operator can run the following **read-only**
command from an already SSH-authorized Codespace, using the enrolled
SSH host public key in this repo:

```bash
ssh -o StrictHostKeyChecking=yes \
  -o HostKeyAlgorithms=ssh-ed25519 \
  -o "UserKnownHostsFile=$PWD/ops/mnebydns-owner-ssh-known_hosts" \
  -o GlobalKnownHostsFile=/dev/null \
  -o UpdateHostKeys=no \
  root@188.120.254.223 'python3 -' \
  < scripts/mnebydns_instagram_ru_readonly_preflight.py
```

The command must be invoked with this PR branch checked out; it relies on
existing authorized SSH and does not configure or acquire credentials.
It fails if 18443 is occupied, queue 211 is already owned, a tagged canary
iptables rule is present, or the rollback timer appears active. Missing
native libnetfilter_queue is reported separately and must be resolved
during a scheduled test window, **not** by this audit.

**No permanent rollout is warranted by this read-only audit.** A user-space
`curl --connect-to` probe to port 18443 is suitable for TCP transport
research, but the *official unchanged Instagram Android application*
continues to open HTTPS port 443. Achieving a safely isolated mobile
Instagram test on that port requires a dedicated ingress IP or a separately
reviewed per-flow isolation mechanism; neither has been demonstrated on
the current server. Do not route the public Instagram DNS name to this
experimental acceptor.

## Acceptance gates

1. Offline tests and CI green.
2. Read-only server inventory: firewall backend, queue availability and test port verified.
3. Independent rollback validated in a disposable network namespace/test host before production.
4. Controlled on-wire SYN-ACK receive window, TCP segment lengths, checksum and subsequent window update captured and reviewed.
5. Only after step 4, design an independently reversible **dedicated ingress** approach for real Android app on TCP/443. This PR does not enable Instagram in DNS.

References: [TCP RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), [window scaling RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html), [kernel checksum offloads](https://docs.kernel.org/networking/checksum-offloads.html), [prior Instagram diagnostic PR #56](https://github.com/grunvald91/telegram-proxy-infra/pull/56).
