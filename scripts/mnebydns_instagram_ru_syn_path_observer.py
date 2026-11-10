#!/usr/bin/env python3
"""Read-only IPv4 SYN path capture for one approved GitHub runner source.

Does not capture or print application payload, client identifiers, or IPs.
Uses Linux AF_PACKET under pre-existing root SSH only.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import sys
import time
from collections import Counter

SERVER = socket.inet_aton("188.120.254.223")
PORTS = (80, 443, 18443)

def analyze(frame, runner):
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl + 20:
        return None
    tcp = ip[ihl:]
    sport, dport = struct.unpack_from("!HH", tcp, 0)
    flags = tcp[13]
    if (flags & 0x12) == 0x02 and ip[12:16] == runner and ip[16:20] == SERVER and dport in PORTS:
        return ("incoming_SYN", dport)
    if (flags & 0x12) == 0x12 and ip[12:16] == SERVER and ip[16:20] == runner and sport in PORTS:
        return ("outgoing_SYNACK", sport)
    if (flags & 0x04) and ip[12:16] == SERVER and ip[16:20] == runner and sport in PORTS:
        return ("outgoing_RST", sport)
    return None

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 script.py GITHUB_RUNNER_PUBLIC_IPV4")
    ip = ipaddress.IPv4Address(sys.argv[1])
    if not ip.is_global:
        raise SystemExit("Only public source IPv4 may be audited")
    runner = ip.packed
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.settimeout(0.5)
    tally = Counter()
    print("ru_syn_path_capture=READY", flush=True)
    end = time.monotonic() + 16
    try:
        while time.monotonic() < end:
            try:
                packet, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            key = analyze(packet, runner)
            if key:
                tally[key] += 1
    finally:
        s.close()
    for port in PORTS:
        for direction in ("incoming_SYN", "outgoing_SYNACK", "outgoing_RST"):
            print(f"ru_tcp_{port}_{direction}={tally[(direction,port)]}",flush=True)
    print("ru_syn_path_capture=COMPLETE_READ_ONLY",flush=True)

if __name__=="__main__":
    main()
