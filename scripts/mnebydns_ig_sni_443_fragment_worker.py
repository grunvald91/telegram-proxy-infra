#!/usr/bin/env python3
"""Opt-in, strictly IPv4 peer-scoped SYN-ACK TCP/443 fragment research worker.

This changes only the advertised TCP window on a validated SYN-ACK and
recalculates its checksum; it does NOT modify TLS, SNI, payload or routing.
An external supervisor must arm a cleanup watchdog BEFORE any NFQUEUE rule.
Not a guaranteed TSPU bypass or a production fix.
"""
from __future__ import annotations
import argparse
import ipaddress
import logging
import os
import struct

from mnebydns_synack_window_canary import checksum
RU = "188.120.254.223"
DE = "89.125.90.101"
ALLOWED_SERVERS = (RU, DE)
HTTPS = 443
QUEUE = 211
WINDOW = 4

def transform(raw: bytes, *, peer: str, server: str = RU) -> bytes:
    """Pure packet transform; CLI restricts production server to owner VPS IPs.

    Pure function is also exercised with 192.0.2.x in disposable namespaces.
    """
    server_p = ipaddress.IPv4Address(server).packed
    peer_p = ipaddress.IPv4Address(peer).packed
    if len(raw) < 40 or raw[0] >> 4 != 4:
        return raw
    ihl = (raw[0] & 15) * 4
    if ihl < 20 or len(raw) < ihl + 20 or raw[9] != 6:
        return raw
    iplen = struct.unpack_from("!H", raw, 2)[0]
    if iplen != len(raw) or struct.unpack_from("!H", raw, 6)[0] & 0x3fff:
        return raw
    if raw[12:16] != server_p or raw[16:20] != peer_p:
        return raw
    tcp = raw[ihl:]
    tcp_header = (tcp[12] >> 4) * 4
    if tcp_header < 20 or tcp_header != len(tcp):
        return raw
    if struct.unpack_from("!H", tcp)[0] != HTTPS:
        return raw
    # Preserve ECN ECE/CWR and options, reject payload/RST/FIN/PSH.
    if tcp[13] & 0x3f != 0x12:
        return raw
    if struct.unpack_from("!H", tcp, 14)[0] == WINDOW:
        return raw
    out = bytearray(raw)
    struct.pack_into("!H", out, ihl + 14, WINDOW)
    struct.pack_into("!H", out, ihl + 16, 0)
    pseudo = raw[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
    struct.pack_into("!H", out, ihl + 16, checksum(pseudo + out[ihl:]))
    return bytes(out)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", choices=ALLOWED_SERVERS, default=RU,
                        help="Exact owner VPS source IPv4; defaults to original RU canary")
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()
    peer = ipaddress.IPv4Address(args.client)
    if not peer.is_global or str(peer) in ALLOWED_SERVERS:
        parser.error("A distinct global IPv4 peer is required")
    if os.geteuid() != 0:
        parser.error("NFQUEUE requires root")
    from mnebydns_nfq_failopen import arm_parent_death_signal, run_queue
    arm_parent_death_signal()
    logging.basicConfig(level=logging.WARNING)
    run_queue(QUEUE, lambda b: transform(b, peer=str(peer), server=args.server),
              ready_file=args.ready_file, max_len=256)

if __name__ == "__main__":
    main()
