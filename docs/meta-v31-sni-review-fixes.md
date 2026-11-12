# PR 87: RU first-hop SNI measurement and runtime recovery fixes

The experiment targets an ordinary phone TCP/TLS client. The RU dedicated
listener negotiates receive scale zero and advertises an eight-byte window
until the SNI is visible, then forwards unchanged TLS through private WG443
to the DE exact-host Nginx map and certificate-verified Meta origins.

## Packet evidence

The actual receiver process now starts an independent in-memory tcpdump reader
**before listening**. Its filter selects the requested public phone IPv4,
RU ens3, destination RU public IP:443, before DNAT. DNS rewriting alone,
successful recv calls, running services, and server-origin TLS probes never
count as proof of SNI splitting.

The collector reassembles ClientHello bytes (including TLS record fragments)
while retaining original TCP segment boundaries. It records complete target
ClientHellos, split and unsplit names, ambiguous overlap/truncation, unfinished
flows, and uncovered visible Meta hostnames. Per-host events are bounded and
marked partial at the limit; global counters remain authoritative. PCAP and
client addresses are not written to the report.

During the window, a fresh report and its exact receiver PID are required.
After coordinated shutdown, the runner retrieves the finalized report before
reset deletes remote state and saves it as the Actions evidence artifact.
No target ClientHello, an unsplit target, ambiguous boundaries, flow eviction,
parser failure, early EOF, missing drop telemetry or nonzero kernel drops
cannot produce `SNI_SEGMENTATION_OBSERVED`. Failed trials preserve evidence too.

The systemd worker uses KillMode=mixed: SIGTERM reaches Python first, which
closes forwarding, stops tcpdump with SIGINT, drains the pipe, checks capture
exit/drop statistics and writes the final report. The cgroup remains bounded
by TimeoutStopSec and the existing independent cleanup timer.

## Backend and runtime checks

Before publishing the scoped phone DNS view, RU verifies all eleven staged
hostnames using real TLS hostname/certificate validation via the actual
WG 10.66.77.1:443 endpoint. Health checks repeat two TLS controls, verify the
route still uses tg-relay, check both DE services and make a certificate-checked
live DoT request for the unchanged YouTube control route.

These server probes verify the backend half. They do not impersonate the phone
or claim that Android received its scoped DoT answers or completed login/feed.

DE now persists a restore-pending marker before production writes. A failed
reload/restart leaves that marker intact, so retrying rollback/reset applies
the original configuration to the daemon even if the disk files already match.
Write/restart failures on one service do not skip the other. Checkpoints remain
until both restoration and service checks succeed.

## Duration and checks

The manual workflow offers 15 or 30 minutes, defaults to 30, and reserves a
45-minute job budget. Both independent cleanup timers remain at 2400 seconds;
the receiver lifetime remains 2700 seconds. Approval uses the duration-neutral
`CONFIRM_CURRENT_PHONE_IP_AND_SNI_TEST` marker.

Automatic tests are consolidated into two offline workflows. Legacy v16 remote
diagnostics and duplicate v23 contracts remain manually callable. No automatic
production activation is added. The lab checks ordinary and TLS-record-fragmented
ClientHello, real certificate-verified TLS/application integrity, final packet
evidence with zero capture drops, window release, unrelated client windows,
and unchanged global scaling/queue exemptions.

An observed split at the RU interface is evidence about those packets, not a
guarantee about every ISP middlebox. GRO/coalescing or retransmissions can make
capture evidence indeterminate. TLS remains end-to-end; Android login/feed,
unrouted/cached domains, IPv6 ingress and UDP/QUIC need their own observations.

## Shared-client trial / cost review (2026-11-13)

- Owner permits using mode `all` for this experimental window, and accepts
  the fact that the RU :443 NAT rule temporarily handles unrelated HTTPS too.
- The reviewed manual workflow allowed `phone_ip=all`, but the RU UFW rule
  rejected it before activating the route. Corrected: an all-mode UFW accept
  is restricted to connections conntracked as DNAT from the owned RU public
  TCP/443 address/port. Direct unsolicited TCP/18443 remains excluded.
- Removed `push` auto-triggers from 12 historical diagnostic workflows,
  retaining explicit `workflow_dispatch`. This prevents a PR code change
  from launching expensive SSH/remote tests automatically.
- No evidence of actual Android Instagram success is claimed. The receiver
  still requires real client traffic and validated packet capture to prove
  the ClientHello crossed RU ingress with SNI fragmented.
- Important: this experiment is the RU ingress/window-clamp path, not the
  currently deployed direct-foreign YouTube ingress. The two designs cannot
  be assumed equivalent for filtering.
