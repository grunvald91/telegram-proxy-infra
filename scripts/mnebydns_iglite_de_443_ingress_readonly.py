#!/usr/bin/env python3
"""Read-only bounded TCP/443 header observer; no PCAP or client payload stored.

Matches the GitHub runner's SSH public source IP (not guaranteed the
same NAT egress IP as the runner's test socket). Never logs real IPs or
TLS data; only counts and first TCP segment length. Captures no UDP.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import signal
import subprocess
import sys
import time

DE = "89.125.90.101"
MAX_CAPTURE_SECONDS = 19
MAX_PACKETS = 120


def parse_summary(output: str, peer: str) -> dict[str, int | None]:
    counters = {
        "syn": 0,
        "synack": 0,
        "ack_inbound": 0,
        "data_inbound": 0,
        "first_data_bytes": None,
        "rst_inbound": 0,
        "rst_outbound": 0,
    }
    for line in output.splitlines():
        if "Flags [" not in line or "IP " not in line:
            continue
        flags = re.search(r"\bFlags \[([^\]]+)\]", line)
        if not flags:
            continue
        f = flags.group(1)
        # tcpdump -n prints IPv4.host.port using "." before the port number.
        inbound = bool(re.search(re.escape(peer) + r"\.\d+\s*>\s*"
                                 + re.escape(DE) + r"\.443:", line))
        outbound = bool(re.search(re.escape(DE) + r"\.443\s*>\s*"
                                  + re.escape(peer) + r"\.\d+:", line))
        if not (inbound or outbound):
            continue
        if inbound and "S" in f and "." not in f:
            counters["syn"] += 1
        if outbound and "S" in f and "." in f:
            counters["synack"] += 1
        if inbound and "." in f and "S" not in f:
            counters["ack_inbound"] += 1
        if inbound and "R" in f:
            counters["rst_inbound"] += 1
        if outbound and "R" in f:
            counters["rst_outbound"] += 1
        if inbound:
            m = re.search(r"\blength\s+(\d+)(?:\s|$)", line)
            if m and int(m.group(1)) > 0:
                counters["data_inbound"] += 1
                if counters["first_data_bytes"] is None:
                    counters["first_data_bytes"] = int(m.group(1))
    return counters


def main() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Read-only capture requires root")
    tokens = os.environ.get("SSH_CONNECTION", "").split()
    if len(tokens) != 4:
        raise RuntimeError("Expected SSH_CONNECTION source IP and port")
    peer = str(ipaddress.IPv4Address(tokens[0]))
    if not ipaddress.ip_address(peer).is_global:
        raise RuntimeError("Expected public IPv4 runner peer")
    if not shutil.which("tcpdump"):
        raise RuntimeError("tcpdump missing on DE")
    # No payload bytes exposed: tcpdump prints only summary, never hex/ASCII;
    # -s 96 limits captured header length. Output is kept in memory only.
    argv = ["tcpdump", "-i", "any", "-nn", "-l", "-s", "96",
            "-tt", "-c", str(MAX_PACKETS),
            "tcp and port 443 and host " + peer]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    time.sleep(.7)
    if process.poll() is not None:
        raise RuntimeError("tcpdump could not initialize")
    print("de_443_observer=READY_RUNNER_SSH_SOURCE_SCOPED", flush=True)
    try:
        stdout, stderr = process.communicate(timeout=MAX_CAPTURE_SECONDS)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=2)
    counters = parse_summary(stdout, peer)
    print("de_443_observer_ssh_source_assumed_same_as_socket_egress=UNVERIFIED",
          flush=True)
    for name, value in counters.items():
        print("de_443_observer_" + name + "="
              + (str(value) if value is not None else "NONE"), flush=True)
    print("de_443_observer_frames_logged=0", flush=True)
    print("de_443_observer_tls_content_logged=0", flush=True)


if __name__ == "__main__":
    main()
