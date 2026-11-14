#!/usr/bin/env python3
"""Bounded header-only, in-memory synthetic TLS path observer.

No packet dumps, flow IPs, HTTP bodies, raw TLS bytes, or user identities written.
The external interface is limited to our own GitHub runner source IP.
WireGuard stages log only counters and recognized synthetic test SNI presence.
"""
import collections
import datetime
import socket
import ssl
import struct
import sys
import time

CONTROL = b"www.youtube.com"
MEDIA = b"rr1---sn-gxuo03g-ig3s.googlevideo.com"
RU = "188.120.254.223"
DEWG = "10.66.77.1"
RUWG = "10.66.77.2"

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")

def observe(role, probe_ip, seconds):
    assert role in ("RU", "DE")
    if role == "RU":
        assert len(socket.inet_aton(probe_ip)) == 4
    net = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    net.settimeout(.25)
    end = time.monotonic() + seconds
    counts = collections.Counter()
    events = collections.Counter()
    samples = []
    print("OBS_READY", role, stamp(), flush=True)
    while time.monotonic() < end:
        try:
            p, info = net.recvfrom(12288)
        except socket.timeout:
            continue
        if len(p) < 40 or p[0] >> 4 != 4:
            continue
        ihl = (p[0] & 15) * 4
        if ihl < 20 or len(p) < ihl + 20 or p[9] != 6:
            continue
        # Ignore noninitial IPv4 fragments.
        if struct.unpack_from("!H", p, 6)[0] & 0x3fff:
            continue
        src = socket.inet_ntoa(p[12:16])
        dst = socket.inet_ntoa(p[16:20])
        data = p[ihl:]
        sport, dport = struct.unpack_from("!HH", data)
        if sport != 443 and dport != 443:
            continue
        iface = info[0]
        if role == "RU":
            if iface == "ens3" and (
                (src == probe_ip and dst == RU and dport == 443)
                or (dst == probe_ip and src == RU and sport == 443)
            ):
                stage = "EDGE_IN" if dport == 443 else "EDGE_OUT"
            elif iface == "tg-relay" and src in (RUWG, DEWG) and dst in (RUWG, DEWG):
                stage = "WG_TO_DE" if src == RUWG else "WG_FROM_DE"
            elif iface == "lo":
                stage = "RU_LOOP"
            else:
                continue
        else:
            if iface == "tg-relay" and src in (RUWG, DEWG) and dst in (RUWG, DEWG):
                stage = "DE_WG_FROM_RU" if src == RUWG else "DE_WG_TO_RU"
            elif iface in ("eth0", "ens3"):
                stage = "DE_ORIGIN_OUT" if dport == 443 else "DE_ORIGIN_IN"
            elif iface == "lo":
                stage = "DE_LOOP"
            else:
                continue
        offset = ((data[12] >> 4) & 15) * 4
        if offset < 20 or len(data) < offset:
            continue
        flags = data[13]
        body = data[offset:]
        mark = "C" if CONTROL in body else ("M" if MEDIA in body else "")
        if flags & 2 and flags & 16:
            tag = "SYNACK"
        elif flags & 2:
            tag = "SYN"
        elif flags & 4:
            tag = "RST"
        elif body:
            tag = "DATA"
        else:
            tag = "ACK"
        counts[(stage, tag)] += 1
        counts[(stage, "PAYLOAD_BYTES")] += len(body)
        if mark:
            counts[(stage, "SNI_" + mark)] += 1
        # Store a small, bounded number of metadata events. No packet bytes,
        # addresses, ports, seq numbers, or other customers' hostnames.
        # Only public runner-source traffic and synthetic named Hello events
        # are written into event log; WG counts remain aggregate.
        if len(samples) < 100 and (
            (stage.startswith("EDGE") and (tag in ("SYN", "SYNACK", "RST") or bool(body)))
            or mark
        ):
            samples.append((stamp(), stage, tag, len(body), mark or "-"))
    net.close()
    print("OBS_END", role, stamp(), flush=True)
    print("COUNTS_BEGIN",role,flush=True)
    for k,v in sorted(counts.items()):
        print("COUNT",role,k[0],k[1],v,flush=True)
    print("COUNTS_END",role,flush=True)
    for item in samples:
        print("EVENT",role,*item,flush=True)

def client():
    for host in ("www.youtube.com", "rr1---sn-gxuo03g-ig3s.googlevideo.com"):
        print("CLIENT_CASE_START",host,stamp(),flush=True)
        start=time.monotonic()
        try:
            with socket.create_connection((RU,443),timeout=5) as tcp:
                print("CLIENT_TCP_CONNECTED",host,round((time.monotonic()-start)*1000),stamp(),flush=True)
                tcp.settimeout(8)
                with ssl.create_default_context().wrap_socket(tcp,server_hostname=host) as tls:
                    print("CLIENT_TLS_PASS",host,tls.version(),round((time.monotonic()-start)*1000),stamp(),flush=True)
        except Exception as e:
            print("CLIENT_TLS_FAIL",host,type(e).__name__,round((time.monotonic()-start)*1000),stamp(),flush=True)
        time.sleep(2)

if __name__ == "__main__":
    if len(sys.argv)>1 and sys.argv[1]=="observe":
        observe(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif len(sys.argv)>1 and sys.argv[1]=="client":
        client()
    else:
        raise SystemExit("usage: observe ROLE PROBE_IP SECONDS | client")
