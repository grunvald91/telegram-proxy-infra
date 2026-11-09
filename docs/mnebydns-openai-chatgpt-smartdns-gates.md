# MNEBYDNS: OpenAI / ChatGPT Smart DNS expansion specification (2026-11-09)

## Source of truth

Official OpenAI networking recommendations: https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps

This is an engineering plan and **not a deployed or validated working Android ChatGPT route**. The existing five-service checkpoint must not change until an isolated reversible acceptance test.

## First-party candidates for a tightly scoped TLS/SNI routing overlay

Candidates to inspect and test individually: `chatgpt.com` and `*.chatgpt.com` (including `ws.chatgpt.com`), `openai.com` and `*.openai.com` (including `android.chat.openai.com`, `auth.openai.com`, `setup.auth.openai.com`, `chat.openai.com`), `oaistatic.com` / `*.oaistatic.com`, `oaiusercontent.com` / `*.oaiusercontent.com`, `oaistatsig.com` / `*.oaistatsig.com`, and `cdn.openaimerge.com`.

This is **not** a request to block or rewrite arbitrary A/AAAA responses. For all domains, verify genuine TLS origin certificate and Android app behavior, preserve authentic server-to-server TLS, and fail closed on unknown SNI.

Do **not** use wildcard DNS rewriting for unrelated third-party infrastructure: `workos.com`, `cloudflare.com`, `stripe.com`, `intercom.io`, `sendgrid.net`, `sentry.io`, `datadoghq.com`, `workoscdn.com`. The official allowlist includes exact dependencies on these services; if they are truly required for login, test only specific documented hosts and compare against baseline behavior. Routing whole providers can affect unrelated apps and users.

## Protocol and product acceptance

- ChatGPT WebSocket requires `wss://ws.chatgpt.com` and may also use `chatgpt.com` over HTTPS / WebSocket upgrade on TCP 443. Origin TLS passthrough must support long-lived connections and preserve SNI/Host.
- OpenAI documents ChatGPT voice UDP **3478** with TCP **443** as a fallback. DNS + TCP/443 SNI passthrough does not itself tunnel UDP, so a voice acceptance test is needed. Treat UDP voice and any direct-IP traffic as unsupported until independently demonstrated.
- Check IPv4 A, AAAA, HTTPS/SVCB and CNAME behavior. A-only synthesis must not make an unrelated IPv6 or HTTP/3 path bypass, fail unpredictably or use an unapproved backend.
- Test Android app: launch, account login, prompt send/streaming, image uploads, voice connection and reconnect; separately test browser. A passing DNS lookup and TLS handshake is **not** evidence the app works.

## No-regression and experiment gates

1. Preserve byte-for-byte verified German five-service stable checkpoint and existing RU stream routing; never restore the old pre-Gemini original config as an emergency rollback.
2. Run offline hostname conflict tests: must not match Telegram or Meta/Instagram/Threads or any other five service; limit pattern to OpenAI-only first-party suffixes.
3. Stage a separate restricted WireGuard/private-sidecar listener with verified TLS/SNI for selected OpenAI hosts. Confirm external public TCP reachability from operator's mobile carrier before changing DNS (GitHub-hosted runner tests do not necessarily represent mobile reachability).
4. Independently register persistent automatic rollback on both nodes before any public DNS or RU SNI change. Snapshot only owned files and reject operator-owned drift.
5. Enable a brief temporary synthetic A overlay, test official HTTPS/WebSocket/origin certificates and the existing five endpoints, and roll back on any failure. Require Android app confirmation with VPN disabled before permanent deployment.
6. Do not merge an experimental DNS rewrite into the stable baseline on server-only evidence.

## Evidence and limitations

- Official network and WebSocket/voice requirements: https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps
- Existing five-service stable baseline: https://github.com/grunvald91/telegram-proxy-infra/blob/feature/mnebydns-stable-hardening-scale-prep-20261109/docs/mnebydns-stable-to-scale.md
- Previously verified Meta DNS/TLS server-side canary (Android apps **not** working per owner): https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42546177906
