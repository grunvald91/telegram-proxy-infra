# MNEBYDNS — Instagram / Threads domain and transport audit (2026-11-09)

## Release decision (verified)

- ChatGPT was permanently retained on the **German** TLS/SNI backend, **the same route class as Claude and Google**. Five previously working resources were preserved.
- The unsuccessful Instagram / Threads canary was **not promoted**. RU public 443 returned to its original mapping; German Meta-only sidecar and both old canary rollback timers were retired.
- Proof: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42554133052 ; stable German checkpoint `/opt/mnebydns-stable-checkpoints/42553135266`.
- All live app-level claims for Instagram / Threads remain **not verified**. Server-side DoT and original TLS checks do not prove the Android apps are usable.

## Exact source audit

Current temporary experiment is `scripts/mnebydns-meta-overlay.py`. It handles **17 suffix families** and **17 explicit names**, and does not own production after the promotion. Its suffix families:

```
instagram.com cdninstagram.com instagr.am ig.me igsonar.com
threads.com threads.net facebook.com facebook.net
fbcdn.net fbsbx.com fb.com meta.com meta.ai
instagramstatic.com igcdn.com fbcdn.com
```

Thus many domains seen in GitHub reports are **already covered** by suffix matching, including `api.instagram.com`, `graph.instagram.com`, `edge-chat.instagram.com`, `gateway.instagram.com`, `scontent-hel3-1.cdninstagram.com`, `fna.fbcdn.net`, `static.xx.fbcdn.net`, `graph.facebook.com`, `edge-mqtt.facebook.com`, `graph.threads.net`, and `z-p42-chat-e2ee-ig.facebook.com`. Adding these exact names again would be redundant.

**Not covered by any current Meta exact/suffix entry:** `igcdn-photos-e-a.akamaihd.net`, `igcdn-videos-a-0-a.akamaihd.net`, `threadsapp.net`, `otel.atmeta.com`, `giphy.com`. These are **candidate names, NOT proven requests by either app on this device**:

- `igcdn-photos-e-a.akamaihd.net`: specifically mentioned as a media hostname in GitHub diagnostics; stronger candidate if media fails, **not demonstrated as a startup blocker**.
  - https://github.com/remittor/zapret-openwrt/discussions/152
  - https://github.com/Flowseal/zapret-discord-youtube/issues/6481
- `igcdn-videos-a-0-a.akamaihd.net`: found in older Instagram CDN inventories, without proof of usage in 2026 on this phone.
  - https://gist.github.com/LGA1150/1f06631a5c8d3f51be2a
- `threadsapp.net`: listed in an older community host family for Threads. 2025 Threads moved its primary website to `threads.com`, already covered. **Low-priority legacy hypothesis**.
  - https://www.reddit.com/r/pihole/comments/13os9gb
  - https://techcrunch.com/2025/04/24/threads-officially-moves-to-threads-com-and-updates-its-web-app/
- `otel.atmeta.com`: appears in a 2026 Reddit tracking-domain list; likely telemetry, **no proof required for initial login**.
  - https://www.reddit.com/r/nextdns/comments/1vkmfz4/anyone_have_a_list_of_domains_used_to_block_the/
- `giphy.com`: appears in a Reddit discussion about missing GIFs, not Instagram/Threads startup.
  - https://www.reddit.com/r/nextdns/comments/1qush69/instagram_gifs_not_loading_while_i_am_on_nextdns/

Coverage regression test (without modifying prod): `python3 scripts/mnebydns-meta-domain-coverage-audit.py`.

## More serious architectural limitations than host coverage

1. **UDP/QUIC is not routed.** The previous Meta route was CoreDNS A rewrite to RU:443 → RU Nginx `stream` (TCP) → private WG → German Nginx TCP passthrough. **No UDP 443/QUIC relay was installed.** Meta's own engineering confirmed QUIC support in Instagram for Android; a 2026 Meta publication confirms Media over QUIC on Instagram Live ingest. Neither source proves that the specific failure here was caused by QUIC, but a TCP handshake cannot validate the app's possible UDP paths.
   - https://engineering.fb.com/2020/10/21/networking-traffic/how-facebook-is-bringing-quic-to-billions/
   - https://engineering.fb.com/2026/10/12/video-engineering/shipping-media-over-quic-at-meta-scale-for-instagram-live-ingest/
2. **TLS SNI is visible to the client-side network.** Existing German and RU Nginx use TLS `ssl_preread`, and deliberately preserve the *original* `instagram.com` / `threads.com` ClientHello for end-to-end certificate validation. The initial mobile-to-RU connection is not encapsulated or disguised. If mobile-operator DPI drops Instagram/Threads SNI on that path, DNS A rewriting cannot resolve it. **We have not established whether this actually occurred for this mobile operator**; RU-local TLS 7/7 and RU→DE 9/9 only validate the **server** routes, not the mobile-to-RU handshake.
   - https://habr.com/ru/articles/1077682/
   - https://habr.com/ru/articles/1100978/
   - https://github.com/bol-van/zapret/blob/master/docs/readme.en.md
3. **Private DNS only modifies name resolution.** An Android app can use its own DNS transport or direct IPs instead of system APIs. TLS over DoT for system DNS does not itself tunnel all TCP/UDP. Therefore some app flows can bypass our synthetic A answers. No definitive app-specific route capture is available in this project yet.
   - https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html
   - https://support.google.com/pixelphone/answer/2819583?hl=en

Prior Reality Firefox experiment observed destination IPs but did **not** identify reliable app-specific domains because inward and outward flows were initially misclassified. Two IP matches with Meta DNS were **not** proof of Meta-owned traffic. Do not treat those IPs as a verified host list.

## Proposed measurable next test (not yet run)

- **Do not reactivate Meta in production or mass-add third-party domains without evidence.**
- With the real VPN OFF and Android Private DNS ON, capture just Instagram and Threads app connections for a short session. Open-source [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) can list per-app DNS hostnames, TLS SNI, destination IP and TCP/UDP without root. In non-root mode it uses the local Android VPNService and therefore changes the data path and cannot simultaneously use an unrelated VPN. No TLS decryption is required.
- Compare actual hostnames with `meta.SUFFIXES` and `meta.EXACT`. Distinguish:
  - DNS name absent from policy → candidate to test.
  - Name covered but **UDP/443** → missing QUIC path.
  - Name covered, **TCP/443**, resolved to RU but handshake fails only from phone → investigate operator-side SNI/IP filtering.
  - No DNS requests observed → DNS cache, direct IP or custom resolver are possible, not yet proven; repeat with cache reset and device-level capture.
- After identifying the category, stage *isolated* Meta-only changes with a bounded watchdog and explicit Android success criteria; preserve the permanent ChatGPT + five stable checkpoint.

**Conclusion:** At least one non-covered historical CDN hostname was found, but the claim that an omitted domain is the cause of this app startup failure is **not confirmed**. There are independently documented QUIC and SNI possibilities that the previous 9/9 TLS and 15/15 DoT acceptance tests never measured.
