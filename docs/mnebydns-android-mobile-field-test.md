# MNEBYDNS — Android field test checklist

**Status:** Ready for mobile-network participation; NOT yet tested on an Android cellular route.
**Prerequisite:** RU guard generator is staged and tested in CI, but NO persistent per-peer bypass is enabled.

## Test 1 — TCP/443, before TLS/Instagram

Phone: Android, **cellular data from a Russian mobile operator physically in Russia (not roaming)**. Turn OFF Wi-Fi, VPN, proxy applications and any other tunnel. Keep Android Private DNS exactly `dns.mnebyvpn.site`. Do not edit DNS mappings or Instagram app.

1. Open [https://api4.ipify.org](https://api4.ipify.org) **on the phone** using cellular data, not the computer/GitHub Runner. Record the single public IPv4 value. This may be a carrier CGNAT shared address; do not treat it as unique device identity.
2. Open `http://188.120.254.223:443/` in the phone browser, **preserving the explicit http:// scheme and :443 port**. Record the exact browser error or HTTP response, and whether the browser auto-upgrades the scheme to HTTPS. A browser HTTP 400 or TLS/certificate error, where observed, demonstrates a different level of reachability from a TCP timeout; it does **not** prove Instagram routing.
3. Share the phone's observed IPv4, mobile network operator, and whether the phone is physically in Russia. The test controller must refuse any non-public IPv4 and avoid permanent configuration for CGNAT.
4. In a coordinated short window, run the existing GitHub Actions one-peer diagnostic using the now-known **phone public IPv4** (not the runner source) and the existing rollback guard. The phone browser must repeat the exact URL during the brief active interval. Record whether TCP/443 begins responding. Do not present an inactive client as an A/B result.
5. Confirm the emergency timer has been armed **before** changing nftables, remove the temporary exception immediately afterward, then repeat the browser test. Independently verify no tagged rule, no temporary allow-file, original NFQUEUE 210, active Telegram/Nginx, and unaffected DoT.

## Tests 2 and 3 — only after successful mobile TCP/443

- TLS: verify certificate, relevant SNI and ALPN for a correctly configured temporary host without remapping public Instagram domains. Browser TCP success is necessary but not sufficient.
- Official Android Instagram: only after a separately reviewed per-host DNS + TLS reverse-proxy path exists. Ordinary Android Private DNS cannot force an unchanged app to a custom port and cannot decrypt/alter HTTPS traffic. Check Threads separately if desired.
- Do **not** claim Instagram or SNI bypass success based only on TCP established or a TLS certificate error.

## Stop conditions

Do not run field test when the phone is on Wi-Fi/VPN, in international roaming, has an unknown public IPv4, or there is no interactive tester.
Do not run if the RU original generator checksum differs from the known installed version, its backup is missing, queue210 or the Telegram handler is unhealthy, or a previous test rule exists.
No change to the global NFQUEUE 210 rule, production DNS, working Gemini/Claude routes, or shared Nginx configuration in this trial.

**Verified earlier:** [RU staged-generator A/B](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42886577572), [independent post-deployment health audit](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42887008891). Neither is an Android test.
