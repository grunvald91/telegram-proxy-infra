#!/usr/bin/env python3
"""Read-only bounded IPv4 TCP/443 header counters for one test runner.

Never print packet body, client IP, source ports, or identifiers. No service,
network, firewall, sysctl, Docker or proxy configuration changes.
"""
from __future__ import annotations
import ipaddress
import pathlib
import socket
import struct
import sys
import time


def inspect_frame(packet: bytes, runner: bytes, server: bytes) -> tuple[str, int] | None:
    """Return TCP header class and test source port; discard all other packets."""
    if len(packet) < 14 or packet[12:14] != b'\x08\x00':
        return None
    ip = packet[14:]
    if len(ip) < 40 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl + 20:
        return None
    if struct.unpack_from('!H', ip, 6)[0] & 0x1FFF:
        return None  # never decode a fragmented TCP header
    tcp = ip[ihl:]
    sport, dport = struct.unpack_from('!HH', tcp)
    flags = tcp[13]
    if ip[12:16] == runner and ip[16:20] == server and dport == 443:
        if flags & 0x02 and not flags & 0x10:
            return 'in_syn', sport
        if flags & 0x04:
            return 'in_rst', sport
        if flags & 0x10 and not flags & 0x02:
            return 'in_ack', sport
    if ip[12:16] == server and ip[16:20] == runner and sport == 443:
        if flags & 0x12 == 0x12:
            return 'out_synack', dport
        if flags & 0x04:
            return 'out_rst', dport
    return None


def kernel_stats() -> dict[str, int]:
    names = {'ListenDrops', 'ListenOverflows', 'TCPReqQFullDrop'}
    lines = pathlib.Path('/proc/net/netstat').read_text().splitlines()
    for i in range(0, len(lines)-1, 2):
        if not lines[i].startswith('TcpExt:'):
            continue
        keys = lines[i].split()[1:]
        values = lines[i + 1].split()[1:]
        if len(keys) == len(values):
            mapping = dict(zip(keys, map(int, values)))
            return {name: mapping.get(name, 0) for name in names}
    return {name: 0 for name in names}


def capture(runner_ip: str, server_ip: str, duration: float = 19) -> dict[str, int | str]:
    runner = ipaddress.IPv4Address(runner_ip).packed
    server = ipaddress.IPv4Address(server_ip).packed
    if duration < 3 or duration > 25:
        raise ValueError('invalid capture duration')
    # AF_PACKET is read-only, with no promiscuous mode or kernel rule changes.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
        sock.settimeout(0.5)
        before = kernel_stats()
        seen: dict[int, set[str]] = {}
        print('capture_ready=true', flush=True)
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                packet = sock.recv(65535)
            except socket.timeout:
                continue
            event = inspect_frame(packet, runner, server)
            if event:
                kind, sport = event
                if len(seen) < 32 or sport in seen:
                    seen.setdefault(sport, set()).add(kind)
        after = kernel_stats()
    syn_ports = {port for port, kinds in seen.items() if 'in_syn' in kinds}
    result: dict[str, int | str] = {
        'in_syn_flows': len(syn_ports),
        'out_synack_flows': sum('out_synack' in seen[p] for p in syn_ports),
        'in_followup_ack_flows': sum('in_ack' in seen[p] for p in syn_ports),
        'in_rst_flows': sum('in_rst' in seen[p] for p in syn_ports),
        'out_rst_flows': sum('out_rst' in seen[p] for p in syn_ports),
    }
    for k in before:
        result['delta_' + k] = after[k] - before[k]
    if not syn_ports:
        classification = 'no_matching_inbound_syn_observed'
    elif result['out_synack_flows'] == 0:
        classification = 'syn_seen_no_kernel_synack_observed'
    elif result['in_followup_ack_flows'] == 0:
        classification = 'kernel_synack_seen_no_client_ack_returned'
    else:
        classification = 'tcp_handshake_observed'
    result['classification'] = classification
    for key, value in result.items():
        print(f'{key}={value}', flush=True)
    print('read_only_no_payload_or_identity=true', flush=True)
    return result


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: python3 - runnerIPv4 serverIPv4')
    capture(sys.argv[1], sys.argv[2])
