# YouTube playback diagnosis, 14 November 2026

Client context: Android, `dns.mnebyvpn.site`, VPN off, Wi-Fi. Mobile-data testing
showed an empty app; the owner reports likely operator allowlisting, so that
network is not a useful control for the Wi-Fi playback failure.

After the Google API QUIC allowance deployed in a parallel chat, the owner
confirmed that the app loads much faster. Videos still show an endless spinner.
Playback has **not** been restored or verified.

## Verified results

- [Correlated observation](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43618313705):
  both nodes and the tunnel were active. API, image and profile-picture Initials
  were observed. No new `googlevideo.com` ClientHello was identified in the
  observation window. Aggregate observation does not identify a specific phone.
- [Parallel Google API release](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43619383285):
  `*.googleapis.com` was added on both relays, with strict suffix boundaries.
  Real HTTP/3 returned YouTube 200 and Google APIs 404 (a valid HTTP response).
  Installed relay SHA256: `0468e44d74929860722fe922ec156bac04ac49a49452d364df6cc23c87b221da`.
  This release was deployed from `fix/mnebydns-googleapis-quic-20261114`.
  The identical relay and test source is incorporated into this branch after
  local verification; no additional deployment is needed for that allowance.
- [Expanded observation](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43619439247):
  no new video-domain Initial was observed. The first media extraction attempt
  failed because the server Python is older than the current yt-dlp supports.
  A green workflow did not mean the media test passed; it explicitly skipped it.
- [Corrected media test](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43620240184):
  extraction ran with runner Python through authenticated SSH SOCKS to DE89,
  avoiding a different metadata egress IP. Public CC test video `aqz-KE-bpKQ`,
  format 18, produced a signed Googlevideo URL. Range requests returned HTTP
  403 and zero bytes both directly from DE89 and through DE/RU local proxies.
  This is an anonymous synthetic client result; it does not establish the
  native Android app's response or prove an IP-wide Google restriction.
- A local Wi-Fi test using the normal yt-dlp downloader through RU188 also
  fetched metadata successfully and received HTTP 403 for the media. A DoT
  lookup confirmed that the selected CDN host maps to RU188.
- Local Wi-Fi TCP/TLS to RU188 and DE89 succeeded for YouTube and DoT.
- Local Wi-Fi HTTP/3 through RU188 succeeded for `www.youtube.com` (200) and
  `youtubei.googleapis.com` (405). A generic `www.googlevideo.com` probe timed
  out, which alone does not establish that an actual media CDN fails.
- A signed URL selected the public CDN host
  `rr1---sn-gxuo03g-ig3s.googlevideo.com`; its signed IP matched DE89. A full
  HTTP/3 request from local Wi-Fi through RU188 timed out for this actual host.
- [Origin comparison](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43621459392):
  the same CDN host completed verified TLS and HTTP/3 (404 on `/`) when probed
  on RU188 through its UDP relay, WireGuard and DE89. This verifies that host's
  downstream QUIC path, not its signed video body. Direct QUIC from RU to the
  Google origin timed out. The probe emitted asyncio stream-finalization
  warnings but recorded authenticated TLS and an actual HTTP status.
- Aioquic 1.8 client Initials were inspected locally: YouTube, API and actual
  CDN hosts each produced one 1200-byte datagram, and the relay correctly
  extracted all three names. The actual CDN's ClientHello was 498 bytes, so
  the observed failure cannot be explained by fragmentation of that Initial.
- [Coordinated Wi-Fi probes and both-node observation](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43622270861):
  one local process alternated three valid 1200-byte YouTube Initials and
  three valid 1200-byte Initials for the actual CDN. All three YouTube probes
  received 1200-byte replies in 0.089–0.097s; all three CDN probes timed out.
  RU's capture saw exactly three public incoming UDP datagrams / 3600 bytes,
  all with YouTube SNI, and no Googlevideo Initials. DE saw those same three
  requests and returned nine 1200-byte packets, which RU also observed and
  forwarded. ETH_P_ALL was used to include ingress and egress.

## Current diagnosis

Controlled CDN Initials are lost before the observed public ingress of RU188.
This rules out downstream WireGuard/CDN forwarding as the cause of these
specific lost requests. The selective result is consistent with hostname-based
filtering on the client-to-ingress path. It does not identify a particular
operator, router, local filter, or hosting-provider edge as the dropping device.
The coordinated probe used the computer's Wi-Fi path, not a captured Android
flow; the owner's Android playback remains the required product confirmation.

The anonymous downloader's HTTP 403 is a separate finding. It must not be
presented as proof that Google blocks all native Android playback from DE89.
Further downstream proxy or DNS changes do not address the missing test Initials.

No live server configuration was modified by this diagnostic branch.
Temporary media URLs, wheels, dependency directories and SSH SOCKS control
sockets were removed after testing. No client IPs or video URLs were logged.

Five Actions runs were started by this chat. Timing API reported durations
139s, 99s, 69s, 33s and 109s (449s total), and zero billable milliseconds for all.
These are the API values, not an estimate of the account's remaining quota.
