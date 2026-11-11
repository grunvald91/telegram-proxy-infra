# Receiver-driven client SNI segmentation (v15)

Implementation: [receiver](../scripts/meta_v15_receive_window.py),
[15-minute controller](../scripts/meta_v15_phone_trial.py),
[isolated network test](../scripts/tests/integration_meta_v15_netns.py).

This is a new experimental mechanism, not the route-only v11 observer.
It aims to make the **client** transmit the initial TLS bytes in small TCP
segments on the client-to-edge path. It never decrypts TLS or modifies SNI.
It cannot split a ClientHello retroactively after a middlebox has dropped it.

## Mechanism

1. A separate Linux TCP listener sets `TCP_WINDOW_CLAMP=65535` **before listen**.
   The kernel negotiates receive window scale zero on that listener. Existing
   Nginx sockets and the global `tcp_window_scaling` setting are unchanged.
2. nftables redirects TCP/443 for exactly one explicit public client IPv4 to
   that listener. Its SYNACK and early ACK packets advertise a window of eight
   bytes. Socket `SO_MARK` bypasses the existing queue210 transformation for
   this listener's replies only, after verifying the live queue exclusion.
3. The receiver reads a bounded TLS prefix and requests QUICKACK. Once it has
   read a complete SNI, it sets a separate socket mark that disables the
   eight-byte rule. The original bytes are relayed to loopback Nginx:443.
   Kernel-generated window updates now pass unchanged, with negotiated scale
   still zero; there is no fabricated scale option to correct later.
4. The existing reviewed exact-host route engine stages the 11 Meta DNS/SNI
   routes for a 900-second capture. Capture is restricted to the explicit
   client IPv4. Both configuration and full proxy/firewall cleanup watchdogs
   are armed, independently of SSH. Bootstrap time is included in the outer
   deadline check. Cleanup removes only the experiment's table and worker,
   then verifies configuration restoration.

Window scaling semantics: [RFC 7323 section 2.2](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2).
Linux per-socket clamp and QUICKACK:
[tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
Kernel window selection:
[tcp_output.c](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_output.c),
`tcp_select_initial_window`. The unprivileged local socket test independently
checks the negotiated server receive scale and the unchanged global setting.

## Evidence required

The network test creates isolated Linux server/client network namespaces and
a veth link, verifies the real nft rules, and uses a standard Python SSL client
with certificate validation. The client contains no segmentation code. A
server-interface PCAP is parsed in memory to require a complete target SNI
split across observed TCP segments, a zero SYNACK scale, tiny initial segments,
larger segments after release, successful encrypted application exchange,
unchanged non-peer windows, and the queue-exemption mark after reverse NAT.
The test must fail if any of those conditions is absent. Local unit/socket
checks do not substitute for this network test.

Verified lab run at implementation commit `696ac367`:
[Actions 43037228535](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43037228535).
All 53 unit/socket tests passed. The real TLS lab recorded one complete SNI
split, 23 tiny initial segments and 209 larger segments after release; TLS
certificate verification and application payload integrity passed. Non-peer
windows, the exemption mark after reverse NAT, and unchanged global scaling
were also checked. These are lab measurements, not phone measurements.

## Scope and limits

- Source-IP scoping cannot select a hostname before the ClientHello arrives.
  Other new TCP/443 connections from the same public NAT address pass through
  the test listener too. Non-target TLS/other protocols are released and
  relayed after prefix inspection; their initial latency can increase.
- The 64-KiB per-socket clamp remains on test connections after release, so
  client upload performance may differ. It is not a global kernel change.
- This IPv4/TCP mechanism does not transform QUIC/UDP. Exact-route DNS
  suppresses alternate record types as in v11; client transport fallback is
  not assumed to work without measurement.
- Split SNI does not guarantee a DPI bypass: a middlebox may reassemble TCP.
  The Linux lab is not evidence about Android, the user's ISP or Instagram's
  actual login/feed operation.
- A public test-phone IPv4 is required; a GitHub runner/SSH peer must never
  be substituted. NAT IP identification alone does not prove device identity.
- The controller retains one-shot state and refuses duplicate runs. It
  installs same-boot recovery only, consistent with the existing test model.
  Tests and code publication do not automatically activate the live trial.

The manual phone workflow accepts the explicit peer IPv4. Automatic PR CI has
no VPS access or secrets and runs the isolated network lab instead.
