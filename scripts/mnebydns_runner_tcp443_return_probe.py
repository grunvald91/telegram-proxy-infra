#!/usr/bin/env python3
"""One-off, no-server-access IPv4 TCP/443 return-path observation.

Runs on the *GitHub runner*, not the live server. Records no packet contents,
addresses, source ports, credentials or subscriber data. Never changes a server.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time

TARGET = "89.125.90.101"
CONTROL = "example.org"


def packet_event(frame: bytes, destinations: dict[bytes, str]):
    """Return (label, SYN|SYNACK|RST, source_port) for scoped IPv4 traffic."""
    if len(frame) < 54:
        return None
    if frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    hlen = (ip[0] & 0x0F) * 4
    if hlen < 20 or len(ip) < hlen + 20:
        return None
    if struct.unpack_from("!H", ip, 6)[0] & 0x1FFF:
        return None
    tcp = ip[hlen:]
    sport, dport = struct.unpack_from("!HH", tcp)
    flags = tcp[13]
    src_ip, dst_ip = ip[12:16], ip[16:20]
    if dst_ip in destinations and dport == 443 and flags & 0x02 and not flags & 0x10:
        return (destinations[dst_ip], "SYN", sport)
    if src_ip in destinations and sport == 443:
        if flags & 0x12 == 0x12:
            return (destinations[src_ip], "SYNACK", dport)
        if flags & 0x04:
            return (destinations[src_ip], "RST", dport)
    return None


def connect_ipv4(host: str, port: int = 443, timeout: float = 4.0) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return "connected"
        except OSError as exc:
            return type(exc).__name__


def observe() -> None:
    control_ip = socket.getaddrinfo(CONTROL, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    destinations = {
        ipaddress.IPv4Address(TARGET).packed: "foreign443",
        ipaddress.IPv4Address(control_ip).packed: "control443",
    }
    if len(destinations) != 2:
        raise RuntimeError("control and target endpoint must differ")

    # Linux AF_PACKET, no BPF installation, no promiscuous mode, no packet files.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sniffer:
        sniffer.settimeout(0.25)
        observed: dict[str, dict[str, set[int]]] = {
            name: {"SYN": set(), "SYNACK": set(), "RST": set()}
            for name in destinations.values()
        }
        results: list[tuple[str, str]] = []
        completed = threading.Event()

        def client() -> None:
            try:
                for name, host in (("control443", control_ip), ("foreign443", TARGET),
                                   ("foreign443", TARGET), ("foreign443", TARGET)):
                    results.append((name, connect_ipv4(host)))
                    time.sleep(0.20)
            finally:
                completed.set()

        th = threading.Thread(target=client, daemon=True)
        th.start()
        deadline = time.monotonic() + 24
        finished_at = None
        while time.monotonic() < deadline:
            try:
                raw = sniffer.recv(65535)
            except socket.timeout:
                raw = b""
            event = packet_event(raw, destinations) if raw else None
            if event:
                name, kind, sport = event
                if len(observed[name]["SYN"]) < 16 or sport in observed[name]["SYN"]:
                    observed[name][kind].add(sport)
            if completed.is_set():
                if finished_at is None:
                    finished_at = time.monotonic()
                if time.monotonic() - finished_at >= 0.75:
                    break
        th.join(timeout=1)
        if th.is_alive() or not completed.is_set():
            raise TimeoutError("local probe thread did not complete")

    for name in ("control443", "foreign443"):
        syn = observed[name]["SYN"]
        ack = observed[name]["SYNACK"] & syn
        rst = observed[name]["RST"] & syn
        attempts = [result for label, result in results if label == name]
        if not syn:
            classification = "no_outbound_syn_observed"
        elif ack:
            classification = "synack_observed_on_runner"
        elif rst:
            classification = "rst_observed_on_runner"
        else:
            classification = "outbound_syn_but_no_response_observed"
        print(f"{name}_connect_results={','.join(attempts)}", flush=True)
        print(f"{name}_outbound_syn_flows={len(syn)}", flush=True)
        print(f"{name}_inbound_synack_flows={len(ack)}", flush=True)
        print(f"{name}_inbound_rst_flows={len(rst)}", flush=True)
        print(f"{name}_classification={classification}", flush=True)
    print("vantage=github_runner_only", flush=True)
    print("no_remote_server_access_or_changes=true", flush=True)
    print("packet_payload_ip_and_ports_not_logged=true", flush=True)


if __name__ == "__main__":
    observe()
