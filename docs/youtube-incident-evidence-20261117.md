# YouTube incident: verified evidence, 17 November 2026

YouTube playback on the owner's phone is **not restored or verified**. A green
diagnostic job means its commands finished, not that playback works.

## Capture-quality correction, 17 November

**This correction supersedes earlier causal conclusions drawn from absent
packets or incomplete records in the older observer.** Positive packet and
full-record matches remain observations; negative matches do not establish
where a stream stopped.

[Return timing run 44041229081](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44041229081)
reported 41 kernel capture drops and two truncated frames. Older observers
did not report these quality counters. Their reassembly also assigned
`chunks[seq] = body`: a shorter retransmission at the same sequence number
could overwrite a longer previously captured coalesced segment. That is a
confirmed observer defect, not a confirmed explanation of each prior failure.

[Correction 4aa8185](https://github.com/grunvald91/telegram-proxy-infra/commit/4aa8185912c7090c75ace69bde9e42d835028268)
increases the tcpdump buffer to 32 MiB, removes snaplen truncation, preserves
the longest same-sequence payload, and rejects absence-based analysis when
kernel drops or truncated frames are reported. Six offline parser tests and a
specific longer-segment/shorter-retransmission check passed locally.

[Corrected DE89-only run 44041951909](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44041951909)
observed 24,293 frames from 10:51:53 to 10:53:23 Moscow with zero reported
kernel drops and zero truncated frames. It identified 87 target-family
connections: 86 googleapis.com and one ytimg.com. All 87 initial TLS records
were complete, matched Pilot and origin, and had public response payload.
No googlevideo.com connection was identified in this window. This does not
reproduce or resolve the phone's video failure.

The owner's explicit Googlevideo curl timeouts remain valid client-side
observations. The older capture cannot by itself prove missing bytes before
Nginx or exclude a processing defect. A quality-checked capture of the same
failed Googlevideo attempt is still needed.

The owner instructed us to exclude RU188 from further work. No DNS entry was
moved to RU188; the proposed route renderer was local and never applied.
Further diagnostics and fixes are scoped to DE89 only.

## Evidence ledger

| Test | Observed result | What it establishes |
| --- | --- | --- |
| [15 Nov, scoped NFQUEUE bypass](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43704035056) | RU188 public Googlevideo TLS timed out both normally and with a scoped bypass; temporary rule removed. | That bypass did not restore this controlled connection. |
| [15 Nov, scoped MSS64](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43704324554) | TCP established in both cases; TLS timed out with MSS1448 and negotiated MSS52; temporary rule removed. | Smaller advertised MSS did not restore this controlled connection. |
| [16 Nov, public/private path comparison](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43884423646) | RU188 -> DE89 public Googlevideo TLS failed; RU188 -> DE89 private tunnel Googlevideo TLS passed; RU188 local public ingress probe passed at that time. | The public and private paths behaved differently. This is not a phone playback test or proof that today's RU ingress works from the phone. |
| [17 Nov, YouTube API trace](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44007351425) | Three identified API flows had complete 1580-byte TLS records and 6727–6728 public response bytes. | These API flows completed the initial TLS exchange. It does not establish all Googlevideo ClientHellos arrived. |
| [17 Nov, cross-leg prefix matching](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44007351337) | 25 distinct public ClientHello fingerprints; 18 matched Pilot; seven did not. | Prefix fingerprints identify initial bytes; they do not prove full-record receipt or successful video playback. |
| [17 Nov, Googlevideo observation](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44016126071) | 12 identified Googlevideo flows contained 1448 bytes of expected 1755–1851-byte TLS records, with no Pilot match and no public response. | Incomplete receipt was observed in these flows. Exact attribution to the owner's phone was not proven. |
| [17 Nov, Googlevideo cumulative ACK observation](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44017181444) | 17 identified Googlevideo flows were incomplete at 1448 bytes; qualifying outbound WAN ACKs were observed; no Pilot match or public response. | The server emitted ACKs. Capture at eth0 does not prove their delivery to the client or locate the missing tail. |
| [17 Nov, actual owner personal DoT link](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44017973306) | Actual owner label resolved and verified TLS; protected YouTube A answers included DE89; Googlevideo AAAA had no addresses. | DNS bootstrap and these answers worked at test time. Media transfer was not tested. |
| [17 Nov, fresh NFQUEUE differential](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44019061773) | External runner obtained verified TLS and HTTP responses from API, thumbnail and CDN hosts. RU188 obtained API/thumbnail responses, but Googlevideo timed out in baseline, bypass and restored phases. Bypass matched 302 packets and was removed. Neither 35-second passive window contained identifiable Googlevideo flows. | The bypass did not repair the controlled RU188 connection. There is no new phone playback comparison in this run. |

## Current processing configuration observed in the fresh differential

Both shared Nginx and GooglePilot contained the Googlevideo family route:
public TCP443 -> `127.0.0.1:15449` -> `$ssl_preread_server_name:443`.
GooglePilot used the independent Quad9 resolver, IPv6 off, a 16 KiB proxy
buffer and 120-second inactivity timeout. Shared Nginx used a 15-minute
inactivity timeout. All four inspected services were active.

These observations do not prove playback or eliminate every processing defect.
In particular, a request to the CDN root returning HTTP404 is a TLS/HTTP
transport check, not a successful signed `/videoplayback` response.

## Changes made during this investigation

- Reused the previous TCP reassembly/SNI/ACK observer, increased capture snaplen
  to 65535 and bounded each capture at 35 seconds.
- Ran its six offline parser tests successfully before the live operation.
- Temporarily bypassed NFQUEUE for DE89 outbound public TCP443 responses, with
  an independent systemd cleanup timer armed before insertion.
- Removed the rule and verified normal control behavior after restoration.
- Did not deploy persistent DNS, Nginx, GooglePilot, tunnel or subscriber changes.

One new Actions run was started: 44019061773. GitHub's timing endpoint reported
`run_duration_ms=129000` (129 seconds), `UBUNTU.total_ms=0`, and one job. This
is the API's reported telemetry; elapsed time is not an inferred billing charge.

## Requirement before the agreed phone capture

A fresh failed playback attempt must be correlated to the owner's actual client
connection. Then determine whether the complete ClientHello reaches DE89 and,
if it does, follow that exact stream through Pilot, origin response and return
delivery. If it is incomplete again, inspect both ends of the same connection
to distinguish missing client transmission, missing tail delivery and ACK return
failure. Do not call a prefix match, HTTP404/403, an empty capture, or a green
diagnostic job proof of repaired playback.


## Agreed phone window, 17 November, 07:51:24–07:54:24 Moscow

[Run 44020006136](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44020006136)
verified packet-reader readiness before the owner was instructed to open YouTube.
It captured 26469 frames over 180 seconds, without configuration changes.
Complete initial TLS records were compared by full-record HMAC across public
ingress, Pilot and origin egress; this is stronger than the older prefix test.

| Anonymous source in this capture | Host family | Flows | Complete records / Pilot / origin matches | Public response bytes observed |
| --- | --- | ---: | ---: | ---: |
| e176bbba38 | googlevideo.com | 11 | 0 / 0 / 0 | 0 |
| e176bbba38 | googleapis.com | 11 | 3 / 3 / 3 | 173257 |
| e176bbba38 | ytimg.com | 2 | 2 / 2 / 2 | 164365 |
| bc2162f08d | googleapis.com | 6 | 6 / 6 / 6 | 60213 |
| bc2162f08d | googleusercontent.com | 1 | 1 / 1 / 1 | 12338 |

All eleven identified Googlevideo flows from the first source had only 1448
contiguous bytes of expected 1744–1851-byte records. Missing bytes per record:
1744 - 1448 = 296 through 1851 - 1448 = 403. Eight API-family flows from that
same source were also incomplete at 1448 bytes. Outbound cumulative ACKs were
observed for all 19 incomplete identified target flows.

All twelve complete identified target records across both sources matched both
Pilot and origin egress and had public response data. No identified complete
record with zero public response was observed. Public byte counters count
captured TCP payload and do not establish useful video playback or client
receipt of every byte.

The source with all eleven media failures is consistent with the agreed phone
attempt, but no subscriber credential-to-source-IP binding was collected; do
not represent source ownership as independently authenticated.

The older observer reported incomplete record receipt and no Pilot match;
the capture-quality correction above prevents using this as reliable localization. It does not establish whether the missing bytes were never
transmitted by the client, dropped in transit, or affected by ACK return loss,
and does not identify a particular network filter.

No persistent fix was applied. One Actions run was started for this agreed
window. The timing API reports run_duration_ms=199000 (199 seconds),
UBUNTU.total_ms=0 and one job; no billing charge is inferred from elapsed time.


## Retrieved successful Termux check from the original chat

A targeted conversation lookup for «Разбор Google Smart DNS» returned the
owner's message at 2026-11-17 03:07:05 UTC (06:07:05 Moscow), followed by the
assistant's response at 03:07:12 UTC. This is a retrieved conversation fragment,
not a complete raw chat export; no canonical conversation URL was returned.

The command was:

```sh
curl -v --noproxy '*' -4 --http1.1 --connect-timeout 7 --max-time 12 --resolve youtubei.googleapis.com:443:89.125.90.101 -o /dev/null https://youtubei.googleapis.com/
```

The retrieved user output includes ClientHello (1573 bytes), ServerHello,
successful Google certificate verification, TLS 1.3 and
HTTP/1.1 405 Method Not Allowed. This is a successful phone-to-YouTube-API TLS
and HTTP transaction and must be retained as positive evidence.

Keep this distinct from the three automated API control flows in
[44007351425](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44007351425):
those logged 1580-byte records and completed their capture at 03:05:06 UTC,
before the successful phone message at 03:07:05 UTC. They must not be attributed
to that later phone test.

Targeted searches did not return a successful phone/Termux Googlevideo CDN
transaction from that original chat. This retrieval limit is not proof that
such a message never existed. The successful API transaction and the later
incomplete Googlevideo records concern different hostnames and connections;
they do not contradict each other.

The owner confirmed after run 44020006136 that images loaded but video did not.

## Explicit Termux Googlevideo test, 17 November, 08:07:21–08:10:21 Moscow

[Run 44021809780](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44021809780)
armed the same bounded observer before the owner was given this command:

```sh
curl -v --noproxy '*' -4 --http1.1 --connect-timeout 7 --max-time 15 --resolve rr1---sn-gxuo03g-ig3s.googlevideo.com:443:89.125.90.101 -o /dev/null https://rr1---sn-gxuo03g-ig3s.googlevideo.com/
```

The owner pasted the resulting output: a five-byte TLS record header, a
1587-byte outgoing ClientHello, no ServerHello, and curl error 28 after
7002 milliseconds.

Exactly one identified Googlevideo flow appeared in the capture. Its expected
TLS record size was 1592 bytes, matching 5 + 1587 from the supplied output.
It had only 1448 contiguous captured client bytes, one captured data-segment
sequence, no Pilot prefix/full-record match, no origin full-record match and
zero public response bytes. Difference: 1592 - 1448 = 144 bytes.

The same anonymous source had five other complete identified target records
(four googleapis.com and one gstatic.com). All five matched complete records
at Pilot and origin egress and had public response data.

The unique target-family/record-size match in the agreed window strongly
correlates this flow with the supplied Termux attempt. No independent
credential-to-source-IP binding was collected. The capture establishes the
bytes observed by this observer; it does not by itself establish where the
uncaptured tail went or prove a specific ISP/DPI mechanism.

No persistent production configuration change was applied. The agreed capture
used one Actions run. The timing API reports run_duration_ms=199000 (199
seconds), UBUNTU.total_ms=0 and one job; no charge is inferred from elapsed time.

## Explicit Termux TLS 1.2 comparison, 17 November, 08:14:24–08:17:24 Moscow

[Run 44021809780, attempt 2](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44021809780/attempts/2)
used the same observer and address/SNI as the preceding test, while curl was
limited with `--tlsv1.2 --tls-max 1.2`.

The owner supplied an outgoing 243-byte handshake plus a five-byte record
header (248 bytes total), followed by no ServerHello and error 28 after
7002 milliseconds. The observer did not identify a Googlevideo flow or a
248-byte target TLS record in that window. Do not report this as a complete
248-byte record received by Nginx. The observer does not emit per-flow
SYN-only entries, so this log does not independently correlate an empty TCP
flow to that attempt.

Nine other target-family records from one anonymous source were complete and
matched Pilot and origin egress. Eight had public response payload. One
gstatic.com record (517 bytes) matched both Pilot and origin; 2805 upstream
response bytes were counted but zero public response bytes. Three complete
initial TLS records overall (including two other host families) had no public
response. Per-flow close/first-response timing and Pilot-to-shared return
bytes were not logged, so this does not yet establish a server forwarding
defect: late upstream response, client closure and return processing remain
unresolved alternatives.

The short TLS 1.2 test also timed out. Therefore the large-record split
observed in the earlier test is not, on its own, a complete explanation.
Neither a specific ISP/DPI mechanism nor absence of server-side defects has
been established. Persistent routes/configuration were unchanged.

## Latest bounded diagnostics budget

Four additional Actions runs were started for path audit (44038097216),
scoped SYNACK comparison (44038815116), return timing (44041229081), and
corrected return timing (44041951909). The SYNACK rule was removed; the last
two runs changed no production service configuration. The first two preceded
the owner's instruction to stop using RU188. Actual billed minutes for these
four runs have not been retrieved and are not asserted.

## DE89-only continuation and current service state

Playback on the phone remains unverified and the owner continues to report
failure, including intermittent loss of thumbnails. No persistent production
DNS, Nginx, GooglePilot, WireGuard or subscriber change was deployed.

- [Processing audit 44043199404](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44043199404): the external runner obtained verified TLS/HTTP404 for 1594-byte TLS1.3 records, including a split at byte 1448, and a 252-byte TLS1.2 record. All four full records matched Pilot/origin and had public replies. Inspected Nginx error logs contained no matching failures; this is not exhaustive proof of absence of all defects.
- [Media attempt 44043950713](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44043950713): the sample BaW_jenozKc was unavailable; media transfer was not tested. Capture had 491 kernel drops and is invalid for absence claims.
- [Corrected capture 44044840455](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44044840455): 11:13:25–11:16:25 Moscow. Zero kernel drops; an 8192-byte intentional packet prefix retained the 4096-byte initial-record budget, with no unsafe short prefixes. One source had two complete API records (1832/1821 bytes), Pilot/origin matches and public replies. Its Googlevideo record expected 1851 bytes but had one retained 1448-byte segment, no Pilot prefix match, no origin match or public response; outbound pure ACKs did not cover the full record. The owner reported an unsuccessful playback attempt during this window. Source ownership remains temporally correlated, not independently authenticated.
- [Window4/scale0 trial 44046041037](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44046041037): only the runner was affected. Three TLS1.3 controls timed out; TLS1.2 eventually succeeded. Phone stage skipped; temporary rule removed and protected configuration hashes unchanged.
- [Preserved-scale trial 44046901134](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44046901134): all four external controls passed with initial advertised window four. No phone media candidate appeared in its 45-second selector, so no phone rule was applied. Cleanup passed.
- [Phone-scoped window trial and actual media range 44047955995](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44047955995): one temporally selected media source was tested from 11:36:12 to 11:37:12 Moscow; the scoped rule matched 37 SYNACK packets and was removed. Video was not restored. The source had 22 ordinary-window Googlevideo records retained at 1448 bytes with no Pilot/origin match or public response, and nine experimental-window media records without a Pilot prefix match or public response. Do not treat the experimental records' retained lengths as complete receipt counters: the old 24-segment retention cap was reached. Three thumbnail records hit that cap yet had public responses and full-record cumulative ACKs, proving this observer limitation. The retention budget was subsequently corrected to cover tiny segments within the first 4096 bytes.
- In that same run, extraction of public test video jNQXAC9IVRw through DE89 succeeded. Its media URL was bound to DE89. Both direct-origin-over-DE89-SOCKS and public DE89 SmartDNS passthrough returned HTTP206, verified certificates and exactly 65536 bytes of video/mp4. Elapsed curl transfers were 0.862356 and 0.807085 seconds respectively. This establishes an actual bounded media transfer from the external runner, not phone playback.
- [Split-handshake trial 44049065156](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44049065156): all external controls timed out, the phone stage was skipped, and the temporary rule was removed with protected configuration unchanged.
- [Kernel receipt observer 44050013495](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44050013495): ordinary TCP rules were confirmed restored, capture reported zero kernel drops and no unsafe prefixes, but no media candidate was observed. No kernel receipt measurement was obtained; do not report kernel-level confirmation.
- [Current personal DNS path 44052431538](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44052431538): nginx, GooglePilot, CoreDNS, personal SNI stream/redirect and original NFQUEUE service active. No experimental TCP rule remains. Personal DoT uses public853 redirected to local8854, with its existing private DNS backend 10.66.77.2:8858; verified TLS1.3 to that backend succeeded from DE89. There was no active DoT socket matching the earlier media source, so no connection was reset and the current personal hostname/actual DNS answers could not be validated. The earlier local8858/inactive-systemd-unit observation was the wrong layer: the private DNS gateway is a remote container, not a DE89 systemd unit.

A targeted search of the original chat did not return the current personal DNS
hostname; earlier assistant messages intentionally omitted it. The credential
attachment does not contain a personal DNS hostname. The missing current
hostname is needed to test the actual configured personal link. Neither a
specific ISP/DPI device nor a universal server-only remedy has been established.

Ten Actions runs were started in this continuation: 44043199404, 44043950713,
44044840455, 44046041037, 44046901134, 44047955995, 44049065156,
44050013495, 44051829232 and 44052431538. Billed minutes for these ten runs
were not retrieved and are not asserted. No further TCP mutation is running.
