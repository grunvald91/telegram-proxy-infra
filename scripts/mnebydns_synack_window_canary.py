#!/usr/bin/env python3
"""Experimental SYN-ACK clamp for a SINGLE dedicated TCP test listener.

Not production Instagram bypass. Never touches shared HTTPS/443 or DNS.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import struct

LOG = logging.getLogger("mnebydns.synack")
TEST_PORT = 18443


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def clamp_synack(packet: bytes, *, server: str, client: str,
                 port: int = TEST_PORT, window: int = 4) -> bytes:
    """Mutate only TCP window and TCP checksum in validated IPv4 test SYN-ACK.

    Preserves TCP Window Scale and all other TCP/IP options. The first client
    data packet is NOT guaranteed to be 4 bytes: measure on the wire.
    """
    if port != TEST_PORT or not 1 <= window <= 65535:
        raise ValueError("Dedicated canary port 18443 and valid receive window required")
    if len(packet) < 40 or packet[0] >> 4 != 4:
        return packet
    ihl = (packet[0] & 0x0f) * 4
    if ihl < 20 or len(packet) < ihl + 20 or packet[9] != 6:
        return packet
    total_length = struct.unpack_from("!H", packet, 2)[0]
    if total_length != len(packet):
        return packet
    frag = struct.unpack_from("!H", packet, 6)[0]
    if frag & 0x3fff:
        return packet
    if packet[12:16] != ipaddress.IPv4Address(server).packed:
        return packet
    if packet[16:20] != ipaddress.IPv4Address(client).packed:
        return packet
    tcp = packet[ihl:]
    if len(tcp) < 20 or struct.unpack_from("!H", tcp, 0)[0] != port:
        return packet
    tcp_hlen = (tcp[12] >> 4) * 4
    if tcp_hlen < 20 or tcp_hlen > len(tcp):
        return packet
    if tcp[13] & 0x3f != 0x12 or len(tcp) != tcp_hlen:
        # SYN|ACK with optional ECE/CWR for ECN; never RST/FIN/PSH/payload.
        return packet
    out = bytearray(packet)
    struct.pack_into("!H", out, ihl + 14, window)
    struct.pack_into("!H", out, ihl + 16, 0)
    pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
    struct.pack_into("!H", out, ihl + 16, checksum(pseudo + out[ihl:]))
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="188.120.254.223")
    parser.add_argument("--client", required=True)
    parser.add_argument("--port", type=int, default=TEST_PORT)
    parser.add_argument("--queue", type=int, default=211)
    parser.add_argument("--window", type=int, default=4)
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()
    for name in (args.server, args.client):
        ip = ipaddress.ip_address(name)
        if ip.version != 4 or not ip.is_global:
            parser.error("server/client must be public IPv4 addresses")
    if args.server == args.client or args.port != TEST_PORT or not 1 <= args.window <= 65535:
        parser.error("Only dedicated port 18443 is permitted; distinct peers required")
    if not 1 <= args.queue <= 65535:
        parser.error("Invalid NFQUEUE number")
    from mnebydns_nfq_failopen import run_queue, arm_parent_death_signal
    arm_parent_death_signal()
    logging.basicConfig(level=logging.INFO)
    LOG.info("Experimental queue: %s:%d -> %s window=%d",
             args.server, args.port, args.client, args.window)
    run_queue(args.queue,
              lambda p: clamp_synack(p, server=args.server, client=args.client,
                                     port=args.port, window=args.window),
              ready_file=args.ready_file)


if __name__ == "__main__":
    main()
