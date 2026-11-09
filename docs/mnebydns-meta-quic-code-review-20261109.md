# Meta DNS/TCP/QUIC implementation review — 2026-11-09

## Verdict

**The Android app remains unverified / not working. Do not claim that QUIC worked end-to-end because CI passed.**

Two owner PCAPs were examined locally (raw captures deliberately not committed):
- 10:29 MSK: 49 outbound UDP/443 Meta QUIC v1 Initial packets, 1252 bytes each; 49/49 accepted by the decoder.
- 11:19 MSK: 85 outbound UDP/443 packets aimed at RU 188.120.254.223:443, 1252 bytes each; 85/85 accepted by the decoder.
- Second capture: 107 TLS ClientHello TCP flows to RU; 105 had no inbound application payload.
- Second PCAP predated the QUIC relay deployment, so it does **not** verify the new UDP path.

## Confirmed implementation/test mistakes

1. **False-positive QUIC success gate.** Prior CI only submitted a synthetic Initial on RU loopback and observed an admitted counter on DE. It never required a real Meta origin response, and never checked DE→RU→client return.
2. **Missing packet-drop observability.** Invalid sizes, unknown peers, overflow and upstream reply counts were absent/underreported; packet drops could not be distinguished from absence of traffic.
3. **Restricted UDP datagram length.** A fixed 1450-byte cap could discard legitimate bigger QUIC server datagrams. The provided captures were 1252 bytes, so this is **not a demonstrated cause**.
4. **Test-host omission.** The old mandatory TLS/DoT checks omitted i-fallback.instagram.com despite its appearance in captured traffic; wildcard DNS/SNI routing already matched the hostname.

## Relevant archived server observations

- Full synthetic admission and auto-rollback: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42601232320
- Historical RU and DE QUIC service counters: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42602739684
  - For each of the two pilots (42590952202, 42601232320), RU admitted=1 and DE admitted=1. Each pilot sent one artificial RU-localhost packet. There is **no evidence of an additional app-sourced admitted flow**. This does not prove which network hop, if any, dropped traffic.
- RU external UDP/443 is permitted by current UFW/nft configuration: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42603270434
  - Cannot rule out remote operator/provider filtering or client transport selection from host firewall policy alone.
- Internal TCP/TLS tests completed; external public SNI reachability had failures: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42587254776
  - TCP SYN reachability is not the same as end-to-end ClientHello/ServerHello success.

## Fixes in this review branch

- Count every UDP packet at the ingress before size/peer/SNI filtering and keep aggregate forward and reverse counters.
- Raise UDP transport cap from 1450 to 8192 bytes while bounding pre-establishment buffers.
- Add test-only upstream injection seam; local CI now checks echo response traverses DE→RU→synthetic client, not just admission. This is an isolated test, **not** a real Meta QUIC handshake.
- Add i-fallback.instagram.com to mandatory TLS and DNS probes.
- Change CI admission status labels to truthfully say `ADMISSION_ONLY`; explicitly state `Meta_QUIC_real_origin_reply_NOT_VERIFIED=true`.
- Keep the existing two-node auto-rollback design. The reviewed branch does **not** auto-deploy to production.

Offline validation: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42604066550

## Still unknown

- Did the Android app attempt UDP during the later live pilot? Archived counters cannot detect pre-socket drops or application decisions.
- Did the mobile operator or upstream network filter visible Meta SNI? No definitive proof from the existing recordings.
- Will the real origin send a QUIC response via public ingress, and will the mobile client receive it? The new synthetic echo test does not settle this.
- DNS rewriting and server-side TLS forwarding **do not hide client-side SNI**. Fixing any blocking before RU requires a client-capable privacy transport such as compatible ECH or an encrypted tunnel, not merely adding DNS suffixes.

**No new mobile capture is requested. No live DNS/Nginx/VPN configuration has been modified by this review branch.**
