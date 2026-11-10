#!/usr/bin/env python3
"""Offline/namespace-only kernel integration probe for SYN-ACK NFQUEUE canary.

Modes: listener, client, worker, verify. All addresses are documentation-only
RFC 5737 addresses, usable only inside test namespaces; no DNS or Internet.
"""
from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
from pathlib import Path

from mnebydns_nfq_failopen import run_queue
from mnebydns_synack_window_canary import clamp_synack, checksum

SERVER = "192.0.2.1"
CLIENT = "192.0.2.2"
PORT = 18443
QUEUE = 211


def listener(ready: str, count: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((SERVER, PORT))
        server.listen(12)
        server.settimeout(12)
        Path(ready).write_text("ready\n")
        for _ in range(count):
            conn, address = server.accept()
            if address[0] != CLIENT:
                raise RuntimeError("Namespace listener received a foreign client")
            with conn:
                conn.settimeout(3)
                block = bytearray()
                while len(block) < 16384:
                    chunk = conn.recv(16384 - len(block))
                    if not chunk:
                        break
                    block.extend(chunk)
                    if b"i.instagram.com" in block:
                        break
                if b"i.instagram.com" not in block:
                    raise AssertionError("Expected authentic TLS ClientHello with SNI")
                print(f"listener_received_tls_clienthello_bytes={len(block)}", flush=True)


def client():
    # Generate a real OpenSSL TLS 1.3 ClientHello without contacting Meta.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = context.wrap_bio(incoming, outgoing, server_hostname="i.instagram.com")
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    assert len(hello) > 100 and b"i.instagram.com" in hello
    with socket.create_connection((SERVER, PORT), timeout=5) as sock:
        sock.sendall(hello)
    print(f"client_sent_tls_clienthello_bytes={len(hello)}", flush=True)


def worker(ready: str):
    run_queue(
        QUEUE,
        lambda data: clamp_synack(data, server=SERVER, client=CLIENT, port=PORT, window=4),
        ready_file=ready,
    )


def pcap_packets(file: str):
    raw = Path(file).read_bytes()
    if len(raw) < 24:
        raise ValueError("No pcap global header")
    magic = raw[:4]
    if magic == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif magic == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    else:
        raise ValueError("Expected classic pcap file")
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    if linktype != 1:
        raise ValueError(f"Expected Ethernet capture, got linktype {linktype}")
    pos = 24
    while pos + 16 <= len(raw):
        _sec, _usec, length, _origlen = struct.unpack_from(endian + "IIII", raw, pos)
        pos += 16
        frame = raw[pos:pos+length]
        if len(frame) != length:
            raise ValueError("Truncated pcap packet")
        pos += length
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            continue
        ipv4 = frame[14:]
        ihl = (ipv4[0] & 15) * 4
        if ipv4[0] >> 4 != 4 or ihl < 20 or len(ipv4) < ihl + 20 or ipv4[9] != 6:
            continue
        total = struct.unpack_from("!H", ipv4, 2)[0]
        if total > len(ipv4):
            raise ValueError("Truncated IPv4 payload")
        tcp = ipv4[ihl:total]
        sport, dport = struct.unpack_from("!HH", tcp, 0)
        hlen = (tcp[12] >> 4) * 4
        if hlen < 20 or len(tcp) < hlen:
            continue
        yield {
            "src": socket.inet_ntoa(ipv4[12:16]),
            "dst": socket.inet_ntoa(ipv4[16:20]),
            "sport": sport, "dport": dport,
            "flags": tcp[13], "window": struct.unpack_from("!H", tcp, 14)[0],
            "payload_size": len(tcp) - hlen,
            "valid_checksum": checksum(ipv4[12:20] +
                                       struct.pack("!BBH", 0, 6, len(tcp)) + tcp) == 0,
        }


def verify(file: str, mode: str):
    packets = list(pcap_packets(file))
    synacks = [p for p in packets
               if p["src"] == SERVER and p["dst"] == CLIENT
               and p["sport"] == PORT and p["flags"] & 0x12 == 0x12]
    if len(synacks) != 1:
        raise AssertionError(f"Need exactly 1 SYN-ACK, saw {len(synacks)}")
    synack = synacks[0]
    if not synack["valid_checksum"]:
        raise AssertionError("Bad on-wire TCP checksum on SYN-ACK")
    if mode == "clamped":
        if synack["window"] != 4:
            raise AssertionError(f"Expected win 4, got {synack['window']}")
    elif synack["window"] == 4:
        raise AssertionError("Reference SYN-ACK unexpectedly had win 4")
    payload = [p["payload_size"] for p in packets
               if p["src"] == CLIENT and p["dst"] == SERVER
               and p["dport"] == PORT and p["payload_size"] > 0]
    if not payload:
        raise AssertionError("No client payload in capture")
    print(f"mode={mode} synack_window={synack['window']} "
          f"synack_checksum_valid={synack['valid_checksum']} "
          f"client_tcp_data_segments={payload}", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("listener", "client", "worker", "verify"))
    p.add_argument("--ready")
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--pcap")
    p.add_argument("--variant", choices=("reference", "clamped", "failbypass"))
    args = p.parse_args()
    if args.mode == "listener":
        if not args.ready:
            p.error("--ready required")
        listener(args.ready, args.count)
    elif args.mode == "client":
        client()
    elif args.mode == "worker":
        if not args.ready:
            p.error("--ready required")
        worker(args.ready)
    else:
        if not args.pcap or not args.variant:
            p.error("--pcap and --variant required")
        verify(args.pcap, args.variant)


if __name__ == "__main__":
    main()
