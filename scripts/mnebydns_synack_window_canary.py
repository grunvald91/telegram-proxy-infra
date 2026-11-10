#!/usr/bin/env python3
"""Experimental IPv4 SYN-ACK receive-window clamp for an ALLOWLISTED test peer.

NOT a production DPI solution. Only the SYN-ACK is changed; Linux's internal
TCP control block is *not* changed. A later ACK may advertise a larger window
and defeat the intended split. Do not modify TCP Window Scale negotiation.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import struct

LOG = logging.getLogger("mnebydns.synack")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def clamp_synack(packet: bytes, *, server: str, client: str,
                 port: int = 443, window: int = 4) -> bytes:
    """Return a modified IPv4 SYN-ACK packet or identical bytes if out of scope.

    Never changes payload, TCP options or the IPv4 checksum. Skips fragments,
    malformed packets and anything outside the exact server/client/port tuple.
    """
    if not 1 <= window <= 65535 or not 1 <= port <= 65535:
        raise ValueError("Invalid TCP window/port")
    if len(packet) < 40 or packet[0] >> 4 != 4:
        return packet
    ihl = (packet[0] & 0x0f) * 4
    if ihl < 20 or len(packet) < ihl + 20 or packet[9] != 6:
        return packet
    total_length = struct.unpack_from("!H", packet, 2)[0]
    if total_length != len(packet):
        return packet
    frag = struct.unpack_from("!H", packet, 6)[0]
    if frag & 0x3fff:  # MF or nonzero fragment offset
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
    if tcp[13] != 0x12 or len(tcp) != tcp_hlen:  # SYN|ACK, no data
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
    parser.add_argument("--client", required=True, help="Single TEST client public IPv4")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--queue", type=int, default=211)
    parser.add_argument("--window", type=int, default=4)
    args = parser.parse_args()
    for name in (args.server, args.client):
        ip = ipaddress.ip_address(name)
        if ip.version != 4 or not ip.is_global:
            parser.error("server/client must be public IPv4 addresses")
    if args.server == args.client or not 1 <= args.port <= 65535 or not 1 <= args.window <= 65535:
        parser.error("Invalid test tuple")
    if not 1 <= args.queue <= 65535:
        parser.error("Invalid NFQUEUE number")
    try:
        from netfilterqueue import NetfilterQueue
    except ImportError as error:
        parser.error("Install python3-netfilterqueue on the TEST host: " + str(error))

    tally = {"changed": 0, "untouched": 0}

    def handle(pkt):
        try:
            original = pkt.get_payload()
            modified = clamp_synack(original, server=args.server, client=args.client,
                                    port=args.port, window=args.window)
            if modified != original:
                pkt.set_payload(modified)
                tally["changed"] += 1
            else:
                tally["untouched"] += 1
        except Exception:
            # Fail open on unexpected data; never stall unrelated connections.
            tally["untouched"] += 1
            LOG.exception("Failed to inspect one packet; passed unchanged")
        finally:
            pkt.accept()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    queue = NetfilterQueue()
    queue.bind(args.queue, handle, max_len=256)
    try:
        LOG.info("CANARY ONLY: server=%s client=%s port=%s window=%s queue=%s",
                 args.server, args.client, args.port, args.window, args.queue)
        queue.run()
    finally:
        queue.unbind()
        LOG.info("Changed SYN-ACK=%s untouched=%s", tally["changed"], tally["untouched"])


if __name__ == "__main__":
    main()
