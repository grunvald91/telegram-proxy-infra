# Meta 15-minute diagnostic: code review, 11 November 2026

Reviewed source: PR [87](https://github.com/grunvald91/telegram-proxy-infra/pull/87),
head `4ec9a6c192b9bdaa821fec61bfd616189c5fe625`.

The implemented live 900-second entrypoint is
[`mnebydns_iglite_route_only_v11.py`](../scripts/mnebydns_iglite_route_only_v11.py).
The later [`meta_v13_isolated_de.py`](../scripts/meta_v13_isolated_de.py)
only validates a separate loopback Nginx process and in-memory route rendering;
it does not implement another live phone trial. Neither implements client SNI
splitting. No live server test or deployment was performed for this review.

## Defects corrected

| Severity | Previous behavior | Correction and regression evidence |
| --- | --- | --- |
| P1 | v11 overrides v10's UNIT/TABLE globals before calling its baseline, so the baseline misses the actual v10 timer/service and global Window20 table. | Explicit read-only checks reject each retired v10 state before starting v11. |
| P1 | SIGTERM/SIGHUP bypass Python's finally cleanup; restoration depends on the later watchdog. | Signals unwind through capture shutdown and configuration restoration; handlers are restored afterward. Repeated TERM/HUP is ignored during restoration. A synthetic live-path SIGTERM test verifies both files and observer cleanup. SIGKILL and reboot remain outside this handler's scope. |
| P1 | Rollback writes one file before validating ownership of the other. An unrelated edit can leave a partial rollback without service reload. A restore-write error also skips all service health commands. | Both ownership checks precede all writes. Restore-write errors are reported after attempting health/reload for restored files. Tests cover drift in either file and a failed Corefile write. |
| P1 | A partly overlapping TCP retransmission can add a boundary inside SNI although another captured segment contains the complete name. | Such evidence is counted as indeterminate, without asserting split/unsplit. Fully redundant retries remain ignored. |
| P1 | tcpdump process failure is not checked/reaped; a premature clean EOF can appear successful. | Check exit status, reject unsolicited EOF, wait/reap the child and close its stream. Synthetic process tests cover failure and normal stop. |
| P1 | DNS validation ignores declared authority/additional sections and trailing bytes. | Parse every declared section, reject malformed/trailing data, alternate address/alias/service records outside the answer section, wrong opcode and extended error codes. A valid empty OPT remains accepted. |
| P2 | The Actions shell exits on SSH failure before printing the captured diagnostic log. | Print the log before propagating the nonzero status. |
| P2 | Observer checks duplicate the consolidated suite; push and PR events can run the same checks twice. | Keep a single automatic PR regression workflow, with concurrency cancellation for superseded offline runs. The older observer workflow remains manually available. |

## Validation

Local isolated checks: **45/45 unit tests passed** (12 v11 runtime/scope,
23 SNI observer, 10 DNS wire). Exact-domain renderer and v13 isolated-preview
self-tests passed. Downloaded workflow YAML and embedded shell syntax passed;
`git diff --check` passed.

The tests mock server commands and use synthetic TCP/DNS data. They do not
establish Android application functionality, public connectivity, current VPS
state, DPI bypass, or reboot recovery. The launch marker was not changed.
The live trial retains its existing one-shot directory guard and same-boot
watchdog; this review does not reset historical state or start another trial.
