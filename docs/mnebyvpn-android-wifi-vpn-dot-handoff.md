# MNEBYVPN: Android Wi-Fi + VPN + Private DNS diagnostics

## Evidence and limits

Android documents that a Private DNS resolver used together with VPN must be reachable both inside and outside the VPN (DevicePolicyManager).

The GitHub runner and DE89 VPN-owner account observe only their own paths. They cannot prove reachability from a particular phone's Wi-Fi, full VPN tunnel, or subscriber profile. Never label server test results as client E2E verified.

## Automated server tests: existing five-minute schedule

The existing workflow .github/workflows/mnebydns-dot-external-five-minute-20261113.yml retains its current five-minute schedule. Besides its old DoT check, it now runs three samples of each path:

1. GitHub runner outside the VPN to 89.125.90.101:853, legacy DoT DNS request and verified wildcard personal-style TLS.
2. Dedicated DE89 service account mnebyvpn-xray to public 89.125.90.101:853, exercising the UID-specific local OUTPUT redirect.

Each sample reports TCP, TLS and DNS phase, elapsed time, sanitized error class. No subscriber key is read or logged.

States: PASS = all samples good; DEGRADED = one of three failed (warning); FAIL = two or more failures of three (workflow fails); UNKNOWN = no valid observation (never pretend healthy). Unavailable external OR VPN-owner vantage fails the monitoring job as a **coverage gap** (not proof of customer outage). A reported DNS success additionally requires a parseable nonempty A answer associated with the requested DNS name (or its CNAME chain).

Unknown generated personal-style hostname only tests the wildcard certificate, NOT authenticated personal DNS. For full subscriber-style testing a separate diagnostic identity is needed.

The GitHub Actions result includes a summary and JSON artifacts retained for three days. Scheduled jobs may be delayed; short sub-minute outages are not guaranteed to be seen. No systemd restarts, routes, iptables/nftables, subscriber data or production configuration are changed.

## Client check on Android (Termux, local-only)

Requires Python 3 and these two files in the same directory:
- scripts/mnebyvpn_android_handoff_probe.py
- scripts/mnebyvpn_dns_vpn_handoff_monitor.py

From that directory, run:

    python3 mnebyvpn_android_handoff_probe.py --seconds 180 --interval 3

The probe attempts to read the assigned Android Private DNS hostname from Android settings. If Android denies reading it, set the DNS hostname locally, without posting the assigned key in chat or public CI:

    export MNEBYVPN_PRIVATE_DNS_HOST='YOUR_ASSIGNED_HOST.dns.mnebyvpn.site'
    python3 mnebyvpn_android_handoff_probe.py --seconds 180 --interval 3

During the three-minute probe, switch from mobile data to Wi-Fi and then enable the VPN without turning off Private DNS. Repeat with VPN off/on on the same Wi-Fi.

It independently measures the Android system resolver and a true DNS-over-TLS query to the assigned personal name using the pinned edge IP. Responses are TLS-verified. Optional Termux:API can supply a Wi-Fi connected hint without logging SSID or BSSID.

Possible classifications:
- system_dns_and_dot_failed: OS DNS and direct personal DoT both failed.
- system_resolver_problem: OS resolver fails but direct personal DoT works.
- private_dot_path_problem: OS resolver works but direct personal DoT fails.
- personal_dot_not_tested: personal hostname unavailable while OS resolver did not fail.
- system_resolver_failed_dot_unverified: OS resolver failed, but personal DoT is unavailable for testing; its state is unknown.

Two consecutive bad samples mark incident_started; a subsequently *verified* healthy system resolver AND personal DoT sample marks incident_recovered. An unavailable personal DoT test cannot count as recovery. Switching from one connected Wi-Fi access point to another can be detected via a memory-only ephemeral HMAC of Wi-Fi identity; raw SSID/BSSID and the HMAC are never persisted, and the Wi-Fi hint requires Termux:API permissions. All data is local in mnebyvpn-handoff-local.jsonl. No personal hostname, SSID, BSSID, IP, credentials or client traffic are saved. The script cannot prove whether VPN is enabled; Android may also serve a system DNS answer from cache.

Truly automatic detection of every network transition needs permissioned Android network-state callbacks or integration with the VPN client. GitHub Actions alone cannot observe Wi-Fi handoffs on a phone.

## Fault interpretation

| Pattern | What is supported | Investigate |
|---|---|---|
| External FAIL, owner PASS | External ingress path differs | TCP/853 ingress, SNI and upstream |
| External PASS, owner FAIL | VPN-process route differs | Owner-UID OUTPUT redirect |
| Both PASS, Android DoT FAIL | Client network or tunnel-specific issue | Android/Wi-Fi/VPN routes |
| Android OS resolver FAIL, direct DoT PASS | System DNS path problem | Android Private DNS and VPN DNS settings |
| DNS PASS, application FAIL | DNS is not the confirmed cause | VPN tunnel and application |
| UNKNOWN | Insufficient information | Repeat same vantage |

References:
https://developer.android.com/reference/android/app/admin/DevicePolicyManager.html
https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows

The Android probe observes traffic from the Termux process, not necessarily
from every app. Per-app VPN exclusions can make its path differ from that of
Karing or other apps; the probe does not independently detect VPN state.
