# MNEBYDNS — Wi-Fi / Android single-flow field diagnostic

This is a **transport-only** test. It does not change Instagram DNS mappings, install a VPN, intercept HTTPS, or prove Instagram works. Existing Telegram NFQUEUE 210 and Nginx remain running.

## GitHub Actions (after this standalone release is merged into main)

Open the repo's **Actions** tab and choose **MNEBYDNS Android Wi-Fi single-flow TCP test (manual)**, then **Run workflow**. For a Wi-Fi trial:

1. On the Android phone, turn **cellular data off**, leave **Wi-Fi on**, and disable VPN/proxy apps. Android Private DNS may stay set to `dns.mnebyvpn.site`.
2. Visit <https://api4.ipify.org> on this same phone. Note its public IPv4 (a shared NAT/CGNAT IP is possible).
3. Before dispatch, open <https://188.120.254.223/> on the phone and record the exact outcome. If a certificate warning appears, do not bypass it or enter credentials.
4. In Actions, enter `phone_public_ipv4`, choose `wifi`, and enter `PHONE_READY`. Start the workflow while actively observing the job log.
5. **Only after** the log prints `phone_test=READY_FOR_WIFI_OR_CELLULAR`, open the one-time `http://188.120.254.223/mneby-...` challenge URL that the workflow prints. The `http://` scheme is intentional; do not submit any credentials. If the browser forces HTTPS and never sends the HTTP request, abort the test rather than claiming a result.
6. Immediately open <https://188.120.254.223/> again. A browser certificate mismatch is not a successful Instagram/TLS test. The remote monitor checks which single TCP source port reaches RU, detects SYN/SYN-ACK/ACK, and optionally adds a temporary exception for that *one TCP five-tuple*.
7. Verify the workflow's `phone_test_rule_absent=true` and `phone_original_queue_preserved=true`, plus its independent server postchecks. Compare the browser error before/during/after.

## Safety and interpretation

The workflow is `workflow_dispatch` **only**, not started on push or a timer. It refuses non-public phone IPv4 values, mismatched server generator SHA, inactive Telegram service, an existing test rule, or failed rollback scheduling.

An observed source port narrows a shared NAT/CGNAT address to one connection; it does not cryptographically authenticate a particular phone. An HTTP challenge is a short-lived coordination signal only. The remote monitor does **not log packet payload**, personal data, or source port. The port appears only inside the transient in-memory nft rule. A 75-second independent systemd timer is scheduled before adding that rule. Normal cleanup deletes the tagged rule without flushing or recreating the original `telegram_nfqws` table.

A logged SYN-ACK only means RU emitted it; an inbound ACK is stronger evidence that the TCP three-way handshake completed. A visible TLS record type is not proof that certificate validation, TLS negotiation, SNI handling, or official Instagram succeeded.

**Wi-Fi and cellular are both technically testable**. The results apply only to the specific Wi-Fi ISP or mobile operator path used during the trial. A Wi-Fi test does not establish the behavior of Russian cellular DPI.

The previous GitHub-runner A/B baseline and server postcheck are available at:
- <https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42886577572>
- <https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42888349948>

No need to merge the large experimental PR #68 to enable this workflow. This standalone release includes only the phone probe, its tests, this runbook and a separate CI gate.
