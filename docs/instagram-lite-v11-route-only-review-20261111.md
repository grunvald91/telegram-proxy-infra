# Instagram Lite: v11 route-only diagnostic — 11 November 2026

## Evidence from v10

[GitHub Actions #43008699524](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43008699524) completed a 900-second DE trial. 11 Meta host routes were set and a subsequent rollback verified original nginx/CoreDNS and normal TCP scaling. The kernel counters recorded 5,925 matches to experimental ACK rules, but the SNI observer counted **zero complete target ClientHello**. The observer saw 173 non-target SNI values, and could not identify the phone. The user reported that Instagram Lite did not load and YouTube did not load on a separate computer using the DNS. This report does **not** prove that packet window manipulation caused the YouTube failure; it did affect all HTTPS traffic on the VPS, so collateral impact is plausible.

Phone PCAPdroid capture has link type RAW-IP, not the server's Ethernet capture; it shows attempts to both actual Meta IPs and the DE gateway. It is not proof of the external Wi-Fi source address, packet boundaries on the public uplink, or complete handshake on DE.

## What changed in v11

- [Route-only v11](../scripts/mnebydns_iglite_route_only_v11.py) adds **only 11 exactly verified Meta domains** to active CoreDNS/nginx, with no generic origin proxy and byte-reversible per-host rendering.
- **No global `net.ipv4.tcp_window_scaling=0`; no nftables window/mark manipulation**. Original TCP scaling must be enabled before the trial, and is checked rather than written.
- Dedicated `v11` state directory and transient 1,200-second rollback timer; rollback touches only changed nginx/CoreDNS files. A second timer firing after successful rollback does not restart healthy services.
- [Passive in-memory SNI observer](../scripts/mnebydns_iglite_sni_observer.py) now reports incomplete ClientHello record counts, visible SNI in partial records, payloads observed without a SYN, missing first bytes, and short (e.g. 20-byte) record prefixes. No peer IP addresses or PCAP files are stored.
- Old v10 global Window20 live CLI entrypoint disabled, while its rollback remains usable for old state.
- Existing on-request GitHub Action is repointed at v11 and both jobs are **explicitly `if: false`**. The future launch marker is `ops/mnebydns-iglite-v11-launch.marker`, which has **not** been created.

## Limitations and next acceptance gates

v11 **does not implement SNI splitting**. It tests whether the DNS/Nginx routing path receives a complete or partial ClientHello without disrupting unrelated TCP window settings. Success cannot be described as Instagram bypass unless a real phone completes content loading.

Even with only Meta routes changed, nginx reload and DNS restart may briefly affect other services. Verify unrelated services before and after any future live trial, and stop on regression. Separate clients behind the same Wi-Fi NAT cannot be reliably distinguished by source public IPv4 for initial SYN/SYN-ACK handling, so a claimed per-device Window20 clamp would not be isolated without additional network separation.

Do not launch without checking current server baseline, same-boot rollback availability, remote operator readiness, and explicit authorization for a new observation window. GitHub Actions offline CI verifies code paths only, not actual Android connectivity.
