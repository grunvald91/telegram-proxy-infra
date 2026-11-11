#!/usr/bin/env python3
"""Read-only DE TCP/443 packet-header and NFQUEUE210 counter correlation.

No firewall/config edits, no packet payload retained, no source addresses logged.
Interface eth0 avoids duplicate counts from tcpdump -i any.
"""
from __future__ import annotations
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

DE = "89.125.90.101"
DURATION = 17
PACKET = re.compile(r"\bIP (\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+): .*?\bFlags \[([^\]]+)\]")

def run(cmd, timeout=12):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True).stdout

def queue_counter():
    j = json.loads(run(["nft", "-j", "list", "ruleset"]))["nftables"]
    hits = []
    for item in j:
        r = item.get("rule")
        if not r or r.get("family") != "inet" or r.get("table") != "telegram_nfqws" or r.get("chain") != "post":
            continue
        expr = r.get("expr", [])
        if any(e.get("queue", {}).get("num") == 210 for e in expr):
            counters = [e["counter"].get("packets") for e in expr if isinstance(e.get("counter"), dict)]
            if len(counters) != 1:
                raise RuntimeError("queue210 counter is not unique")
            hits.append(int(counters[0]))
    if len(hits) != 1:
        raise RuntimeError("queue210 rule is not unique")
    return hits[0]

def aggregate(text, peer):
    result = dict(syn=0, synack=0, ack_in=0, rst_in=0,
                  peer_syn=0, peer_synack=0, other_syn=0, other_synack=0,
                  distinct_sources=set())
    for line in text.splitlines():
        m = PACKET.search(line)
        if not m:
            continue
        src, sport, dest, dport, flags = m.groups()
        inbound = dest == DE and dport == "443"
        outbound = src == DE and sport == "443"
        if inbound:
            if "S" in flags and "." not in flags:
                result["syn"] += 1
                result["distinct_sources"].add(src)
                result["peer_syn" if src == peer else "other_syn"] += 1
            elif "R" in flags:
                result["rst_in"] += 1
            elif "." in flags and "S" not in flags:
                result["ack_in"] += 1
        if outbound and "S" in flags and "." in flags:
            result["synack"] += 1
            result["peer_synack" if dest == peer else "other_synack"] += 1
    result["distinct_sources"] = len(result["distinct_sources"])
    return result

def snapshot_synrecv(peer, stop, results):
    while not stop.is_set():
        try:
            text = run(["ss", "-tnH", "state", "syn-recv", "sport", "=", ":443"], timeout=3)
            rows = text.splitlines()
            results["total_peak"] = max(results["total_peak"], len(rows))
            results["peer_peak"] = max(results["peer_peak"], sum(peer in line for line in rows))
        except Exception:
            results["failures"] += 1
        stop.wait(.22)

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "self-test":
        sample = (
            "00:00 eth0 In IP 198.51.100.9.4567 > 89.125.90.101.443: Flags [S], length 0\n"
            "00:00 eth0 Out IP 89.125.90.101.443 > 198.51.100.9.4567: Flags [S.], length 0\n"
            "00:00 eth0 In IP 198.51.100.9.4567 > 89.125.90.101.443: Flags [.], length 0\n"
            "00:00 eth0 In IP 198.51.100.10.4568 > 89.125.90.101.443: Flags [S], length 0\n")
        d = aggregate(sample, "198.51.100.9")
        assert [d[k] for k in ("syn", "synack", "ack_in", "peer_syn", "peer_synack", "other_syn", "distinct_sources")] == [2, 1, 1, 1, 1, 1, 2]
        assert aggregate("", "198.51.100.9")["syn"] == 0
        print("passive_parser_self_test=PASS")
        return
    if os.geteuid() != 0:
        raise RuntimeError("read-only tcpdump needs root")
    tokens = os.environ.get("SSH_CONNECTION", "").split()
    if len(tokens) != 4:
        raise RuntimeError("SSH peer missing")
    peer = str(ipaddress.IPv4Address(tokens[0]))
    if not ipaddress.ip_address(peer).is_global:
        raise RuntimeError("SSH source must be public")
    if DE not in run(["ip", "-4", "-o", "addr", "show"]):
        raise RuntimeError("not the verified DE host")
    before = queue_counter()
    listener = run(["ss", "-ltnH", "sport", "=", ":443"])
    if not listener.strip():
        raise RuntimeError("DE 443 not listening")
    cmd = ["tcpdump", "-i", "eth0", "-nn", "-l", "-tt", "-s", "96",
           "tcp and host " + DE + " and port 443"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(.5)
    if process.poll() is not None:
        raise RuntimeError("tcpdump not running")
    peaks = dict(total_peak=0, peer_peak=0, failures=0)
    stop = threading.Event()
    watcher = threading.Thread(target=snapshot_synrecv, args=(peer, stop, peaks), daemon=True)
    watcher.start()
    print("passive_observer=READY", flush=True)
    try:
        time.sleep(DURATION)
    finally:
        stop.set()
        watcher.join(timeout=3)
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            out, err = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate(timeout=3)
    after = queue_counter()
    results = aggregate(out, peer)
    for k, value in results.items():
        print("passive_" + k + "=" + str(value), flush=True)
    print("passive_q210_total_delta=" + str(after-before), flush=True)
    for k, value in peaks.items():
        print("passive_synrecv_" + k + "=" + str(value), flush=True)
    print("passive_queue_delta_is_global_not_attributed=true", flush=True)
    print("passive_tcp443_source_from_ssh_same_as_runner=UNVERIFIED", flush=True)
    print("passive_packet_payload_recorded=false", flush=True)
    print("passive_changes_to_server=NONE", flush=True)

if __name__ == "__main__":
    main()
