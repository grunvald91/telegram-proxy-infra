# MNEBYDNS Instagram SNI experiment — isolated SYN-ACK canary

**Status 10 November 2026:** The **opt-in queue210 guard generator code is installed on the RU VPS**, with the client allow-list **disabled**. The separate TCP/18443 window-clamp experiment has **not** been deployed. Android Instagram E2E is **not yet verified**.

## RU live install and regression evidence — 10 November 2026

1. [Read-only generator fingerprint #42885120840](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42885120840) verified the actual installed `/usr/local/sbin/telegram-nfqws-rules` matched the repository's legacy snapshot byte-for-byte (SHA-256 `c95ea1ad1bc1b801fef6c7ce1d89a99c93d5c823595b605aaf595480607c0cb6`).
2. [Guarded generator installation #42885852171](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42885852171) backed up the exact original to `/var/backups/mnebydns-nfqws/telegram-nfqws-rules.42885852171.bak`, then atomically installed a version with an **optional per-public-IPv4 SYN-ACK exception** (new SHA-256 `8beeffbe10e7da097e10bde4b1ef568219d52c2f1c04b189e71602069de9ec3f`). This did **not restart the service, rewrite live nftables or activate any allow-list**.
3. [Live staged-generator canary #42886577572](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42886577572): GitHub runner TCP/443 failed in 3 pre-test attempts; using the installed generator with a **temporary one-peer allow file under /run** allowed TCP/443 to connect, with 3 packets matching its SYN-ACK exception; after normal removal it failed in 3 further attempts. A systemd timer was armed for independent emergency deletion. This exercise temporarily recreated **only** the `telegram_nfqws` nft table; it did not restart Telegram, DNS, Nginx, or WireGuard.
4. [Independent post-deploy read-only audit #42887008891](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42887008891) passed ten server checks: guarded script SHA, backup SHA, original queue210 rule, no experimental guard, Telegram and Nginx services active, HTTPS listener, queue210 handler bound, absent persistent allow-list and absent temporary peer file. External certificate-validated DoT queries remained successful; Gemini and Claude still returned DE routing.

**Production distinction:** Source code for *an opt-in exception* is installed durably, but the exception is **not enabled for any client**. External connection failures on TCP/443 remain after a test ends; no global traffic bypass is asserted. The installed generator will recreate the original queue210 path on service restart as long as the default allow-IP file is absent. Do **not** add a broad allow-list or imply that official Instagram works based on a single GitHub runner A/B.

**Next field gate:** plan an explicit, temporally bounded Android mobile-provider TCP/443 test, using only one validated public source IP while acknowledging CGNAT shared-IP caveats. Do not modify Instagram Smart DNS mappings until ingress and TLS routing are separately verified.

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

## RU NFQUEUE 210 controlled A/B — measured success (10 November 2026)

A **live, narrowly scoped** GitHub Actions run was authorized and executed:
[Actions #42880528120](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42880528120),
commit `7bb97d9`. It used the runner's public IPv4 as observed by the
pinned-host-key RU SSH connection and checked its equality with public HTTP
egress IP before any firewall modification. The experiment restricted the
temporary `nft return` rule to **outbound TCP SYN-ACK from RU:443 to the
single runner IPv4**, never changing the existing `queue 210` rule or
stopping `telegram-nfqws.service`.

| Phase | Outcome |
| --- | --- |
| Before | Three TCP/443 connection attempts failed (timeout/error) |
| Scoped SYN-ACK queue-210 bypass active | TCP/443 connection **succeeded** |
| Scoped bypass rule counter | **3 packets, 180 bytes** |
| Immediate nft rule cleanup | **DONE** |
| GitHub Actions tagged-rule absence check | **PASS** |
| After rollback | Three TCP/443 connection attempts failed again |

The remote agent pre-armed an independent systemd timer with 95-second
expiry before insertion, and removed the rule after a 55-second active
window. GitHub Actions verified the rule was absent after immediate
cleanup. **The workflow succeeded.** This shows a reproducible
correlation with a strong A/B indication that the RU postrouting
NFQUEUE-210 processing path prevents TCP/443 setup **from this runner**.
It does **not** prove a particular user-space verdict inside `nfqws`,
all-operator behavior, or operation of the unchanged Android Instagram
application. No ClientHello/SNI was transmitted during the TCP-only A/B.
Other DPI limitations remain open.

Next decision: investigate the scope of the existing
`inet telegram_nfqws post` mark + queue rule and plan a separate,
regression-tested SYN-ACK-only exception that leaves all other Telegram
handling intact. Do not generalize a one-peer A/B into a global
production firewall change without testing other ingress and egress
paths. Verify after-test stable services, existing queue-210 service,
and permanent absence of experimental rules.

## Experimental persistent fix: optional per-peer SYN-ACK guard (not deployed)

**Rationale:** the preserved RU generator
`legacy-mtproxy/live-snapshot/server188/usr/local/sbin/telegram-nfqws-rules`
executes `nft delete table inet telegram_nfqws` and then recreates the
`post` chain and its NFQUEUE 210 rule. A manually inserted A/B rule
would therefore disappear when `telegram-nfqws.service` reapplies the
generator (its `ExecStartPost`).

New offline renderer: `scripts/mnebydns_nfqws_synack_guard_render.py`.
It accepts only the known generator shape and leaves all original rules
intact. It inserts an **opt-in** rule before the existing NFQUEUE 210 rule,
which matches all of the original critical predicates and additionally
requires exact RU source IPv4, an explicitly enrolled destination peer
IPv4 and `SYN|ACK` TCP flags. The exemption returns from the current
postrouting base chain (policy ACCEPT) rather than sending the packet to
userspace. It cannot be used to match an Instagram SNI, as SYN-ACK precedes
ClientHello.

Enrolment uses **one** root-owned regular file:
`/etc/mnebydns/telegram-synack-canary-ipv4`. The generator validates
that it contains one global IPv4 address, is not a symlink and is not
group/world writable **before** it deletes/recreates any nft table.
With no file present, its behavior is identical to the original
generator. Rendering alone writes no server files or rules.

Safe offline check from the PR branch:

```sh
python3 scripts/mnebydns_nfqws_synack_guard_render.py --check \
    legacy-mtproxy/live-snapshot/server188/usr/local/sbin/telegram-nfqws-rules
python3 -m unittest discover -s scripts/tests -p 'test_mnebydns*.py' -v
sudo bash scripts/tests/integration_mnebydns_nfqws_guard_restart_netns.sh
sudo bash scripts/tests/integration_mnebydns_nfqws_guard_real_tcp_netns.sh
```

Validated with real Linux nftables in isolated network namespaces:
- A service-style `apply` recreates the bypass ahead of queue 210
- Missing enrolment file recreates only the original NFQUEUE 210 rule
- Malformed, symlink or group/world-writable enrolment files refuse
  changes **before** the existing table is deleted
- Genuine TCP SYN-ACK from the allowed peer matched the exemption
  (**one packet**) and the connection succeeded
- A second, unlisted peer also connected, without incrementing the
  exemption counter

Evidence: [GitHub Actions #42884179798](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42884179798)
and its later hardening runs.

**Not yet done:** confirm the exact current installed
`/usr/local/sbin/telegram-nfqws-rules` contents/sha256 against the
preserved source, review its runtime nfqws flags (which may intentionally
process SYN-ACK), install this opt-in generator on RU, or validate
Telegram under real subscriber traffic after a controlled service
restart. The attempted extension of the pinned-SSH audit workflow for
live generator fingerprinting was blocked by tool safety checks; the
block has not been bypassed. Do not merge this experimental PR or apply
the generator from the repository snapshot without the live comparison,
a verified original-file rollback and a maintenance window.

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


## 11 November 2026 — actual HTTPS/443 SNI segmentation experiment (not deployed)

Earlier side-by-side SNI tests in the project discussion reported Instagram
TLS SNI 0/6 vs control SNI 6/6, and QUIC SNI 0/4 vs control 4/4.
This is strong evidence of an SNI-dependent failure on that test path.
These tests do not prove which specific DPI implementation or every network.

The proposal based on the supplied research is a bounded experiment with
server-controlled segmentation of the phone's *original* ClientHello.
The approach DOES NOT encrypt, substitute, or erase SNI. If the filtering
device correctly reassembles TCP, it may still reject the connection.

Implementation in this PR:
- scripts/mnebydns_ig_sni_443_fragment_worker.py: strict per-peer SYN|ACK
  Window=4 transformer on RU TCP/443, TCP checksum repaired, original
  TLS payload untouched. NFQUEUE211 handler requires fail-open support.
- scripts/mnebydns_ig_sni_443_field_canary.py: time-limited 65s test
  for exactly one public IPv4; first arm independent systemd 100s rollback,
  then install exact OUTPUT NFQUEUE211 and one exception *before* existing
  NFQUEUE210 in the live telegram_nfqws chain. Does NOT stop/recreate
  telegram-nfqws, DNS, Nginx, or WireGuard.
- Per-peer AF_PACKET metadata: count real TCP SYN, SYN-ACK, client first
  4-byte payload segments, and server response packets. Never log TLS
  payload, SNI string, NAT source port, or original IPv4 address.
- Tests: packet checksums, scope, fail-closed packet filters, mocked
  rollback, original 18443 regression and REAL nftables+iptables rule
  installation/cleanup in a disposable Linux network namespace.
  Example CI: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42914972582

Mandatory live release gates, NOT yet complete:
1. Verify test Android's current public IPv4; a prior Wi-Fi IPv4 may
   have changed. Shared CGNAT makes per-IP testing less isolated.
2. Arrange a SHORT, INDEPENDENTLY GUARDED DNS and DE SNI route so that
   the unchanged Instagram Lite app actually reaches RU:443. Existing
   PR #79 is a DE-direct PREVIEW, not a live Android/RU route. A CoreDNS
   global rewrite would affect other subscribers and must not be
   activated without its own rollback and blast-radius review.
3. During an opt-in test window on Wi-Fi, verify on-wire four-byte
   first data segments, returned server TLS data, and real loaded Lite
   feed on the phone with only Android Private DNS configured.
4. After the timer expires, verify all test rules removed, original
   Telegram queue210 intact, DoT and existing Gemini/Claude routes
   unchanged. No global production enablement on synthetic success.
5. Treat ECH, client-side VPN, and client-side Zapret as different
   architectures; a DNS A/AAAA rewrite cannot force an unchanged
   application to enable ECH or locally change its ClientHello.

Status: CODE AND OFFLINE CI ONLY. No live RU/DE changes.


## Measurement hardening review — 11 Nov 2026

**Why earlier green CI was insufficient:** the 443 observer previously counted a
4-byte first data packet by remote source port without proving the preceding
SYN/SYN-ACK/ACK sequence or that the matching observed SYN-ACK had window=4.
Other same-IP flows (e.g. shared NAT) could contaminate counts. Server payload
packets are not proof of completed TLS or a loaded Instagram feed.

**Now fail-closed as transport evidence:**
- Associate packets to an observed TCP SYN with original sequence number, a
  matching SYN-ACK (correct acknowledgment and window=4), and a matching client
  ACK before classifying the initial TLS-looking payload segment.
- Require a TLS record header prefix, source TCP initial sequence, deduplicate
  retransmissions, skip IPv4 fragments, expose untrusted/mixed flows, invalidate
  measurements when capture state overflows. Label requested window=4 as a
  configuration until an outgoing packet really confirms the window.
- Do not label packet counts as full TLS, origin certificate validation or
  successful operation of the Android app. Public IPv4 is **not** a unique
  Android identity behind CGNAT.
- Add counterexample unit tests (orphan data, wrong ACK, ordinary-window flow,
  non-TLS data, duplicates, IP fragments, flow cap).

**Verified GitHub Actions:**
- [Measurement/counter and kernel-rule tests](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42918380064) PASS.
- [Read-only public RU/DE network baseline](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42918742690) PASS as a **measurement**, not a working Instagram route. Runner→RU TCP 443 and 18443 timed out, runner→DE TCP 443 timed out; DE DoT 853 passed certificate verification; Instagram A records remained direct.
- [Exact native NFQUEUE/443 on-wire kernel test](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42919236821) PASS. In isolated 192.0.2.0/24 namespaces with checksum offloads disabled, the reference SYN-ACK window was 65160 with first data segment 1448 bytes; the active 443-specific worker produced window=4 with valid TCP checksum and first client data segment 4 bytes; handler-death bypass restored window=65160 and first segment 1448 bytes. On the clamped run, the client still sent other segments (212 and 72 bytes among them). **Segmentation does not prove a DPI bypass** if the observer reassembles TCP.

**Not done:** no live production firewall/DNS change, no verified RU→DE→Meta path for the unchanged Instagram app, no field trace from the user's phone or mobile operator. This draft must not be advertised as a working Smart DNS Instagram fix.
