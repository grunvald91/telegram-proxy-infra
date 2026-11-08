# MNEBYVPN Gemini: repeatable, bounded, user-triggered route observation

## What is and is not observable

The subscriber HTTPS URL is a bearer profile import link, **not** a historical
log. Existing MNEBYVPN isolated child Xray has `loglevel: warning`, its stdout
and stderr redirected to `/dev/null` by the agent, and no retained access log.
Previous application requests therefore cannot be reconstructed.

The new inspector enumerates outbound **socket metadata already held by the
dedicated Xray child**. Individual subscriber identity per socket is not available. It does not inspect IP
packets, TLS/QUIC payloads, speech, request bodies, Google account or
subscription secrets, and does not restart or reconfigure Xray. A mapping of
Google hostnames to addresses is resolved at measurement time to suggest
**candidate** service domains; IP co-hosting and dynamic DNS mean this never
proves the hostname of a recorded connection.

It prints **only** bounded aggregate transport/port counts and official-Google
candidate hostname associations. Raw destination IPs, client source IPs,
account ids and credentials are not printed or uploaded. GitHub Actions
retains step output under the repository's configured Actions retention
policy; no persistent monitoring service, telemetry daemon or logfile is
installed on the foreign VPS.

## How to run (installed in default branch)

Use the manually dispatched workflow:
`Actions → MNEBYVPN Gemini one-client route diagnostics (private metadata) → Run workflow`.

- Choose `preflight` for a quick, read-only safety check. During feature
  branch development only, a push of this workflow/source file automatically
  runs *preflight only*.
- Choose `capture-exclusive` only after confirming that ALL VPN sessions on this isolated node belong to the operator. This is a manual attestation, not technical subscriber identity proof. The job validates the enabled-account roster,
  identifies its isolated Xray child, resolves known Google host candidates,
  collects **15 seconds idle baseline**, prints
  `GEMINI_TEST_WINDOW_OPEN_UTC`, samples outbound sockets for **90 seconds**,
  then ends. The customer should use only MNEBYVPN and open native Gemini,
  first a short text prompt, then short voice interaction in this 90s window.
  A change in the enabled account count or the Xray child process stops the test. Many TCP tunnels can belong to a single app: the tunnel count is not a user count.
- The report separates baseline destinations, all test destinations and
  destinations newly seen during the activity window. Existing reused sockets
  may be invisible in the newly seen set. There is no capture after 90s.
- Future tests use the same manual workflow, or an owner-confirmed one-off commit titled `[gemini-capture] owner confirmed exclusive test` to `ops/diagnostics/mnebyvpn-gemini-capture-request.txt` on branch `diagnostics/mnebyvpn-gemini-on-demand`. The diagnostics branch must be created after the workflow merges into `main`. No VPN service restart is needed.
- Keep unrelated Android apps closed where practical. Many simultaneous
  tunnels can belong to one VPN app. Background Google Play Services can
  still generate traffic. The test **cannot prove per-Android-app or
  per-subscriber attribution**, so the operator must confirm exclusive use
  before every capture.

## Results to compare

1. Subscriber report: native Gemini text, native voice and Gemini Live
   success/failure, recorded separately.
2. Foreign node socket counts: TCP/443 vs non-443 TCP, UDP and unknown hosts,
   while keeping personal IPs out of public CI logs.
3. Candidate endpoints compared with official
   [Gemini firewall reference](https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/gemini-app-firewall-settings)
   and public MNEBYDNS DoT policy.
4. Confirm each candidate with an additional scoped DNS/TLS acceptance test,
   *before* updating DNS. **Never** blindly redirect Android FCM (5228–5230),
   UDP traffic, time/NTP or other non-HTTPS services to TCP/443-only SNI
   gateway. Source:
   https://firebase.google.com/docs/cloud-messaging/network-configuration

## Safety guarantees / limitations

- Ordinary preflight requires a single established tunnel, often unrealistic for normal VPN apps. Explicit `capture-exclusive` permits multiple tunnels only when all connected sessions are declared to be operator-owned, and stops on changed account roster or Xray child. DO NOT run for real multi-user production traffic: attribution would not be safe.
- Child process identity and configuration topology verified; no global
  tcpdump, pcaps, system logs or all-account log scan.
- No persistent on-server file, daemon, firewall change, config reload or
  secret leakage; only explicit GitHub manual dispatch or an owner-confirmed
  one-off diagnostic branch commit can start capture.
- Without encrypted-client-to-destination metadata or opt-in per-client
  Xray sniffing, the final **exact** Google hostname corresponding to each
  socket is not guaranteed by IP correlation. Do not assert more than observed.
- The workflow is now on `main`, and the
  `diagnostics/mnebyvpn-gemini-on-demand` branch is available for subsequent
  owner-confirmed one-off tests.
- Some addresses may be reused or accessed directly on Android rather than
  through this VPN; no server-only detector can prove that they are used by
  Gemini itself.

Code references:
`scripts/mnebyvpn-gemini-socket-observe.py`,
`tests/test_mnebyvpn_gemini_socket_observe.py`,
`.github/workflows/mnebyvpn-gemini-route-diagnostics.yml`.

## Deployment evidence

- [Verified CI and live socket count](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42514440410): six offline tests PASS; live preflight returned NOT_READY for single-tunnel mode because multiple simultaneous Xray connections existed. This is **not** an observed Gemini session.
- [Merged safe diagnostic code PR #46](https://github.com/grunvald91/telegram-proxy-infra/pull/46); no server process or configuration changes.
