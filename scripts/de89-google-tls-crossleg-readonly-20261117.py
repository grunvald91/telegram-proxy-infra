#!/usr/bin/env python3
"""Bounded read-only TCP metadata trace: public DE89:443, local Pilot:15449.

Never logs payloads, SNI, certificates, or clear client IPs/ports. The two
Nginx sockets cannot be paired conclusively by packet headers alone:
loopback counts are timestamp-correlated hints, NOT exact flow attribution.
"""
import collections
import hashlib
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import time

PUBLIC = "89.125.90.101"
LOOPBACK = "127.0.0.1"
MAX_SECONDS = 75
PACKET = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s+(?:\S+\s+)?(?:(?:In|Out)\s+)?"
    r"IP\s+(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s+>\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):.*?"
    r"Flags\s+\[([^\]]+)\].*?\blength\s+(\d+)"
)

def parse_packet(line):
    """Return timestamp, 4-tuple, flags, payload bytes or None."""
    match = PACKET.search(line)
    if not match:
        return None
    t, src, sp, dst, dp, flags, size = match.groups()
    return float(t), src, int(sp), dst, int(dp), flags, int(size)

def classify(packet):
    _, src, sp, dst, dp, _, _ = packet
    if dst == PUBLIC and dp == 443:
        return "PUBLIC_IN", (src, sp)
    if src == PUBLIC and sp == 443:
        return "PUBLIC_OUT", (dst, dp)
    if src == LOOPBACK and dst == LOOPBACK and dp == 15449:
        return "PILOT_IN", (src, sp)
    if src == LOOPBACK and dst == LOOPBACK and sp == 15449:
        return "PILOT_OUT", (dst, dp)
    if dp == 443 and dst != PUBLIC:
        return "UPSTREAM_OUT", (src, sp, dst, dp)
    if sp == 443 and src != PUBLIC:
        return "UPSTREAM_IN", (dst, dp, src, sp)
    return "OTHER", (src, sp, dst, dp)

def queue210():
    try:
        for line in open("/proc/net/netfilter/nfnetlink_queue", encoding="ascii"):
            row = line.split()
            if len(row) >= 9 and row[0] == "210":
                # proc columns: queue_number peer_portid queue_total copy_mode
                # copy_range queue_dropped user_dropped id_sequence ...
                return {"owned": True, "pending": int(row[2]),
                        "kernel_dropped": int(row[5]),
                        "userspace_dropped": int(row[6])}
    except (OSError, ValueError, IndexError):
        pass
    return {"owned": False}

def audit():
    print("TRACE_READ_ONLY=true", flush=True)
    print("TRACE_NO_PAYLOAD_OR_SNI=true", flush=True)
    print("TRACE_MAX_SECONDS="+str(MAX_SECONDS), flush=True)
    for unit in ("nginx", "mnebydns-googlepilot", "mnebydns-dot", "telegram-foreign-nfqws"):
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=6)
        print("UNIT_"+unit+"="+(r.stdout.strip() or "UNKNOWN"), flush=True)
    listening = subprocess.run(["ss", "-Hlnpt",
        "( sport = :443 or sport = :15449 or sport = :853 )"],
        capture_output=True, text=True, timeout=6)
    ports = set()
    for line in listening.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            ports.add(fields[3])
    for port in sorted(ports):
        print("TCP_LISTEN="+port, flush=True)
    print("Q210_START="+str(queue210()), flush=True)

def trace():
    salt = secrets.token_bytes(32)
    totals = collections.Counter()
    flow = collections.defaultdict(collections.Counter)
    times = collections.defaultdict(dict)
    seconds = collections.defaultdict(collections.Counter)
    first_time = None
    raw = parsed = 0
    target = os.environ.get("DIAG_TARGET_IPV4", "").strip()
    if target:
        address = ipaddress.IPv4Address(target)
        if address.is_private or address.is_loopback or address.is_multicast:
            raise ValueError("DIAG_TARGET_IPV4 must be a public IPv4 address")
    filter_expr = "tcp and ((host "+PUBLIC+" and port 443) or (host "+LOOPBACK+" and port 15449))"
    command = ["timeout", str(MAX_SECONDS), "tcpdump", "-i", "any",
               "-nn", "-tt", "-l", "-s", "96", "-c", "90000", filter_expr]
    print("TRACE_TARGET_IP_PROVIDED="+str(bool(target)).lower(), flush=True)
    print("TRACE_ARMED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), flush=True)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            raw += 1
            packet = parse_packet(line)
            if packet is None:
                continue
            t, src, sp, dst, dp, flags, size = packet
            leg, peer = classify(packet)
            if leg == "OTHER":
                continue
            parsed += 1
            if first_time is None:
                first_time = t
            sec = max(0, int(t-first_time))
            typ = "DATA" if size else "CTRL"
            totals[leg+"_"+typ] += 1
            totals[leg+"_BYTES"] += size
            seconds[sec][leg+"_"+typ] += 1
            if leg not in ("PUBLIC_IN", "PUBLIC_OUT"):
                continue
            if target and peer[0] != target:
                continue
            # Only the same public 4-tuple is treated as a confirmed match.
            key = (peer[0], peer[1])
            f = flow[key]
            if "first" not in times[key]:
                times[key]["first"] = t
            times[key]["last"] = t
            if leg == "PUBLIC_IN":
                if "S" in flags and "." not in flags:
                    f["SYN"] += 1
                if size:
                    f["CLIENT_PKTS"] += 1
                    f["CLIENT_BYTES"] += size
                    f["CLIENT_MAX_SEGMENT"] = max(f["CLIENT_MAX_SEGMENT"], size)
            elif leg == "PUBLIC_OUT":
                if "S" in flags:
                    f["SYNACK"] += 1
                if size:
                    f["SERVER_PKTS"] += 1
                    f["SERVER_BYTES"] += size
            if "R" in flags:
                f[leg+"_RST"] += 1
            if "F" in flags:
                f[leg+"_FIN"] += 1
    finally:
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
    print("TRACE_FINISHED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    print("TRACE_TCPDUMP_EXIT="+str(code),flush=True)
    print("TRACE_RAW_LINES="+str(raw),flush=True)
    print("TRACE_PARSED_PACKETS="+str(parsed),flush=True)
    for key in sorted(totals):
        print("TOTAL_"+key+"="+str(totals[key]), flush=True)
    print("PUBLIC_DISTINCT_FLOWS="+str(len(flow)),flush=True)
    failed = [(key,f) for key,f in flow.items()
              if f["CLIENT_BYTES"] >= 900 and f["SERVER_BYTES"] == 0]
    print("PUBLIC_CLIENT_LARGE_NO_SERVER_DATA="+str(len(failed)),flush=True)
    # Explicitly show the flow's own server response count, including
    # small TLS records: old diagnostics discarded response sizes <100.
    candidates = sorted(
        ((key, f) for key,f in flow.items() if f["CLIENT_BYTES"] >= 900),
        key=lambda pair: times[pair[0]]["first"]
    )
    for key,f in candidates[:40]:
        ticket = hashlib.sha256(salt+repr(key).encode()).hexdigest()[:12]
        start = (round(times[key]["first"]-first_time,3)
                 if first_time is not None else 0)
        print("FLOW_ID="+ticket+" SEC="+str(start)
              +" CLIENT_BYTES="+str(f["CLIENT_BYTES"])
              +" CLIENT_MAX_SEGMENT="+str(f["CLIENT_MAX_SEGMENT"])
              +" SERVER_BYTES="+str(f["SERVER_BYTES"])
              +" SERVER_PKTS="+str(f["SERVER_PKTS"])
              +" SYNACK="+str(f["SYNACK"])
              +" CLIENT_RST="+str(f["PUBLIC_IN_RST"])
              +" SERVER_RST="+str(f["PUBLIC_OUT_RST"]), flush=True)
    for sec in sorted(seconds):
        if sec >= MAX_SECONDS:
            continue
        subset={k:v for k,v in seconds[sec].items()
                if k in ("PUBLIC_IN_DATA", "PUBLIC_OUT_DATA",
                         "PILOT_IN_DATA", "PILOT_OUT_DATA")}
        if subset:
            print("SECOND="+str(sec)+" LEG_COUNTS="+str(subset).replace(" ",""),flush=True)
    qend=queue210()
    print("Q210_END="+str(qend),flush=True)
    print("Q210_PACKET_LOSS_DELTA_KNOWN="+str(qend.get("owned",False)),flush=True)
    print("FLOW_TO_PILOT_MAPPING=NOT_PROVEN_BY_HEADER_CAPTURE", flush=True)
    print("TRACE_FIREWALL_UNCHANGED=true",flush=True)
    if code not in (0,124) or parsed == 0:
        raise RuntimeError("TRACE_NO_USABLE_PACKETS")
    if not totals["PUBLIC_IN_DATA"] or not totals["PUBLIC_OUT_DATA"]:
        raise RuntimeError("TRACE_CONTROL_PUBLIC_BOTH_DIRECTIONS_NOT_VERIFIED")
    print("TRACE_PUBLIC_BOTH_DIRECTIONS_CONFIRMED=true",flush=True)

if __name__=="__main__":
    audit()
    trace()
