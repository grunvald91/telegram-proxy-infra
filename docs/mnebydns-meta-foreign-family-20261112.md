# Meta / Instagram via existing foreign Google route (12 Nov 2026)

## Owner request

Treat Instagram as an app ecosystem, not 11 static DNS names. Cover complete
dynamic hostname families and send their DNS answers to the same foreign
ingress IP as YouTube/Google while preserving the already-working routes.

## What is prepared (OFFLINE ONLY)

Renderer: scripts/mnebydns-meta-foreign-family-render-20261112.py

- Reuses existing public DoT ingress 89.125.90.101, Nginx stream SNI
  dispatcher and GooglePilot loopback 127.0.0.1:15449.
- Adds A reply for Meta names to foreign ingress; suppresses AAAA, HTTPS,
  SVCB and CNAME alternatives for the targeted names, as in earlier Google pilot.
- Adds a matching Meta SNI regex to shared Nginx map, so matching TCP/443
  goes to existing GooglePilot service.
- Adds a matching Meta SNI regex to GooglePilot's $experimental_origin
  map, where it resolves the actual Meta hostname using its external resolver
  and relays TLS unchanged.
- Covers 17 suffix families (Instagram/Meta/Facebook/Threads and CDNs)
  plus 3 individually scoped Akamai aliases. No blanket *.akamaihd.net wildcard.
- Leaves existing Google/Antigravity/Claude/X/TikTok routing, WireGuard,
  packet queues and sysctls untouched.
- Does NOT provide UDP/443 forwarding: native Instagram QUIC is a separate
  problem; fallback to TCP is not proven.

This code only renders three candidate config files plus a JSON manifest.
It DOES NOT install them, activate a GitHub Actions live job, or change the
running services. No activation is implied by a PR merge. It rejects
unexpected or already-owned maps instead of overriding other routes.

## Prior evidence and why this is a distinct test

- 9 Nov experiment routed 17 Meta suffixes through RU ingress 188.120.254.223,
  then private WG to foreign; server checks passed but native Android app
  success was not established:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42546177906
- Another 9 Nov canary verified 12 Meta origin TLS paths and target DoT
  routes, again without confirmed Android app functionality:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42583884583
- Matched ClientHello tests identified selective SNI-dependent loss for
  i.instagram.com and graph.instagram.com on the tested RU/foreign path;
  reusing foreign ingress does NOT guarantee bypass:
  https://github.com/grunvald91/telegram-proxy-infra/pull/56
- Live Google/YouTube foreign 15449 route:
  https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43243224897
- Previous global TCP changes affected YouTube; this design never touches
  global TCP scaling or packet queues:
  https://github.com/grunvald91/telegram-proxy-infra/pull/79

## Acceptance before any live activation

1. Obtain fresh READ-ONLY snapshots from all three current server paths:
   /opt/mnebydns-dot/Corefile,
   /etc/nginx/nginx.conf and
   /etc/mnebydns-googlepilot/nginx.conf.
2. Run the renderer on those exact inputs; inspect all three diffs.
   Check for DNS and SNI ownership overlaps and any stale checkpoints.
3. Validate generated DNS syntax using the deployed CoreDNS binary, and
   both Nginx configs with their actual include paths. Verify foreign->Meta
   TLS certificates with original hostnames and non-proxy DNS resolution.
4. Install a trusted, independently tested recovery path before any writes;
   preserve all three original configs and restore across interrupted rollout.
   Do not reuse previously blocked recovery installer procedures.
5. Apply all three config changes atomically or roll back; DNS must not
   point to an ingress without corresponding SNI and origin handlers.
   Probe A/AAAA/HTTPS/SVCB/CNAME, Meta TLS via 15449, YouTube, Gemini,
   Antigravity, Claude and ordinary direct domain on same live VPS.
6. Test real Instagram app on Russian Wi-Fi and cellular: login, feed,
   reels, uploads and media. Confirm that direct foreign TCP/443 is reachable
   from the device. Do not treat a green server TLS test as app success.
7. Only after E2E success decide whether to make rules persistent and
   separately evaluate UDP/QUIC and new dynamic CDN families.

Domain coverage is a historical working inventory, NOT a claim that all
current Meta endpoints are known. Native apps may use previously unseen
suffixes or literal IP addresses.

## Offline invocation

python3 scripts/mnebydns-meta-foreign-family-render-20261112.py self-test

python3 scripts/mnebydns-meta-foreign-family-render-20261112.py render --dns SNAPSHOT_CORE --shared-nginx SNAPSHOT_SHARED --googlepilot SNAPSHOT_PILOT --out-dir EMPTY_DIRECTORY

Status: NOT DEPLOYED.
