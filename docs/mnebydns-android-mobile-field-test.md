# MNEBYDNS — Android Wi-Fi and cellular field tests (PR #68)

**Stage:** Test harness implemented in the experimental branch. No real Android/Wi-Fi trial has been performed yet. RU:443 ingress was previously tested from an independent GitHub Runner, NOT from a phone. Instagram/Threads DNS routes remain unchanged.

## Purpose and network coverage

- **Wi-Fi is supported.** Test Wi-Fi now even when cellular coverage is poor. The result characterizes that Wi-Fi network/ISP only.
- A separate cellular test is useful later to characterize the mobile operator; it is not a prerequisite for Wi-Fi support.
- Wi-Fi or cellular can be in any country. Do not claim findings about Russian operator DPI from foreign Wi-Fi or roaming.
- Turn off VPN, proxy and other traffic-tunneling apps for the test, keep Android Private DNS configured as usual. This direct-to-IP test **does not need DNS**; a separate DoT and Instagram test follows only if TCP and TLS work.

## How the phone is distinguished from the GitHub Runner

`.github/workflows/mnebydns-android-wifi-field-test.yml` is **manual workflow_dispatch only**. It takes `phone_public_ipv4`, `access_network` (wifi/cellular), and the explicit confirmation `PHONE_READY`. Unlike the legacy Runner A/B test, it NEVER substitutes the GitHub Runner public IP for the phone IP.

The server's `scripts/mnebydns_phone_tcp_flow_probe.py`:

1. Verifies installed generator SHA, Telegram handler and original NFQUEUE 210 rule, with no experimental guard already active.
2. Opens a **read-only AF_PACKET listener** and announces `phone_challenge_ready=true`. An unrecognized challenge or inactive phone causes **no firewall changes**.
3. Waits for a one-time `http://188.120.254.223/mneby-<nonce>` request from the stated public IPv4 on TCP/80. This is a participation signal, **not** cryptographic identity verification.
4. Watches the first subsequent inbound TCP/443 SYN from that IPv4 and learns its **observed NAT source port**. Records a passive baseline for that one connection; if SYN-ACK or ACK is already seen, it skips any firewall change. An outgoing SYN-ACK alone does NOT prove the phone received it.
5. Arms an independent systemd timer **before** adding a temporary rule matching RU source IP, phone public destination IP, **observed NAT TCP destination port**, and SYN-ACK flags. It only bypasses the existing queue210 rule for that **one TCP 5-tuple**; the original nft table and Telegram worker are never restarted or recreated.
6. Separately reports observed SYN, SYN-ACK, ACK and initial TLS handshake-record markers (without logging payload), plus the exception rule's packet counter. This is not a full TLS handshake or Meta certificate verification.
7. Removes the tagged rule by its exact nft handle and verifies that the original queue is present. The independent timer remains a fallback if the SSH session ends unexpectedly. GitHub Actions also runs a separate read-only postcheck.

The test permits a short interval for active phone participation, with no nft changes while awaiting the initial HTTP challenge.

## Android procedure

1. Connect the phone to the Wi-Fi network you want to test. Turn off cellular data for this **Wi-Fi-specific** test (so the browser cannot silently switch networks), plus VPN and proxies. Keep Private DNS `dns.mnebyvpn.site` unchanged.
2. On **that phone**, visit [https://api4.ipify.org](https://api4.ipify.org) and record the external IPv4. It can be shared by other users behind NAT.
3. Before starting Actions, try [https://188.120.254.223/](https://188.120.254.223/) in the browser. Record the exact error. A certificate mismatch means HTTPS got farther than a TCP timeout; **do not proceed past the certificate warning or transmit credentials**.
4. From GitHub Actions, manually start **MNEBYDNS Android Wi-Fi single TCP flow field test (manual only)** on the experimental branch, enter the phone IPv4, choose `wifi`, and enter `PHONE_READY`. This workflow must be available on GitHub's default branch before GitHub exposes manual dispatch in the Actions UI; until that release gate is met it is **code-ready, not launch-ready**.
5. In that run's logs, wait for `phone_test=READY_FOR_WIFI_OR_CELLULAR`; open the **exact HTTP** URL shown in `PHONE STEP A`, with the `http://` prefix, without entering credentials. If the browser forces HTTPS-first upgrades, use an HTTP-only capable client (e.g., `curl` in Termux) or stop — the server must NOT silently authenticate another request.
6. Open [https://188.120.254.223/](https://188.120.254.223/) promptly after the challenge while the same Wi-Fi is active. A browser certificate warning is expected because an HTTPS site certificate normally does not cover the bare IP.
7. Look for `phone_challenge_seen`, `phone_baseline_synack`, `phone_single_flow_rule_active`, `phone_observed_synack`, `phone_observed_ack`, `phone_observed_tls_record_start`, `phone_exception_counter`, and the four `phone_postcheck_...=PASS` statuses. Do **not** mark a missing phone request as success.
8. After the workflow finishes, try the HTTPS address again and record the outcome. Any improvement observed only during the scoped rule would support a transport-level nfqws diagnosis, **not** Instagram loading. Telegram and normal DoT must remain healthy.

## NAT/CGNAT limitations and privacy

A public IPv4 is **not** a unique phone ID. The HTTP challenge demonstrates only a fresh request from that public address; the first subsequent SYN could theoretically be another subscriber behind the same CGNAT. The temporary rule is narrower (IP **plus exact observed TCP port**) rather than an unrestricted IP-wide exception, but is **not cryptographic device authentication**. Do not use this as a mechanism for issuing individual DNS subscriptions or measuring a customer's traffic.

The workflow challenge nonce appears in a public repository's Actions log. It is a very short-lived test correlation value, **not a private authentication secret**. No HTTP payload content, login credentials or source port are printed by the server observer. Only use a disposable test URL; never submit confidential information.

## Interpreting results

| Observed | What it proves | What it does NOT prove |
| --- | --- | --- |
| Incoming SYN at RU | Network reaches RU:443 | That a SYN-ACK returned |
| Outgoing SYN-ACK | Server emitted a response | Phone received it |
| Incoming ACK | TCP handshake likely completed | Working HTTPS or Instagram |
| Incoming TLS record (0x16) | Client sent a TLS handshake record | Full TLS negotiation, valid certificate, SNI bypass |
| Browser page or certificate error | Browser reached a later network stage | That the official Instagram app works |
| No phone challenge | Nothing conclusive | A field-test failure of the service |

## Stop conditions

Abort without changes if the phone IP is unknown/invalid, VPN is active, no test participant is ready, the installed generator SHA differs, NFQUEUE 210 is unhealthy, existing test guards are present, or the watchdog cannot be armed. Do not create a blanket source-IP allowlist. Do not change production Instagram DNS entries, Nginx, Telegram service, or shared TCP/443 policy during this protocol.

**Prior independent evidence:** [Runner A/B](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42886577572) and [postdeploy health](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42888349948).

**Further tests:** TLS certificate and SNI behavior must be verified separately under a valid server configuration. An unchanged Android Instagram client cannot be made to bypass arbitrary HTTPS blocking by private DNS alone: DNS can change IP resolution but not enforce a special TCP destination port or decrypt TLS.
