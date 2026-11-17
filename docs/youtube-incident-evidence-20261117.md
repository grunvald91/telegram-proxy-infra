# YouTube incident: verified evidence, 17 November 2026

YouTube playback on the owner's phone is **not restored or verified**. A green
diagnostic job means its commands finished, not that playback works.

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

## Remaining requirement

A fresh failed playback attempt must be correlated to the owner's actual client
connection. Then determine whether the complete ClientHello reaches DE89 and,
if it does, follow that exact stream through Pilot, origin response and return
delivery. If it is incomplete again, inspect both ends of the same connection
to distinguish missing client transmission, missing tail delivery and ACK return
failure. Do not call a prefix match, HTTP404/403, an empty capture, or a green
diagnostic job proof of repaired playback.
