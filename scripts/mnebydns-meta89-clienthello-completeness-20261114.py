#!/usr/bin/env python3
"""Read-only, source-IP-scoped TCP ClientHello completeness check at foreign 89.

Only a synthetic GitHub runner is observed, not other users. No raw packet
dumps, no application data, no credential collection, no service mutations.
"""
import collections
import datetime
import socket
import ssl
import struct
import sys
import time

FOREIGN = "89.125.90.101"
FAMILIES = (
    "instagram.com", "cdninstagram.com", "instagr.am", "ig.me",
    "igsonar.com", "threads.com", "threads.net", "facebook.com",
    "facebook.net", "fbcdn.net", "fbsbx.com", "fb.com",
    "meta.com", "meta.ai", "instagramstatic.com", "igcdn.com", "fbcdn.com",
)
SUBDOMAINS = (
    "www.instagram.com", "i.instagram.com", "graph.instagram.com",
    "edge-chat.instagram.com", "api.instagram.com",
    "scontent.cdninstagram.com", "video.cdninstagram.com",
    "www.threads.com", "www.threads.net", "graph.threads.net",
    "graph.facebook.com", "b-graph.facebook.com", "scontent.xx.fbcdn.net",
    "static.xx.fbcdn.net", "z-m-gateway.facebook.com",
)
EXACT_CDNS = (
    "instagramstatic-a.akamaihd.net",
    "igcdn-photos-e-a.akamaihd.net",
    "igcdn-videos-a-0-a.akamaihd.net",
)
HOSTS = FAMILIES + SUBDOMAINS + EXACT_CDNS


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def sni_from_hello(d):
    """Parse only the SNI metadata of a complete TLS ClientHello record."""
    if len(d) < 9 or d[0] != 22 or d[5] != 1:
        return None
    end = 5 + int.from_bytes(d[6:9], "big") + 4
    if end > len(d):
        return None
    p = 9 + 2 + 32
    if p >= end:
        return None
    n = d[p]; p += 1 + n
    if p + 2 > end:
        return None
    n = int.from_bytes(d[p:p+2], "big"); p += 2 + n
    if p >= end:
        return None
    n = d[p]; p += 1 + n
    if p + 2 > end:
        return None
    ext_len = int.from_bytes(d[p:p+2], "big"); p += 2
    limit = min(end, p + ext_len)
    while p + 4 <= limit:
        typ = int.from_bytes(d[p:p+2], "big")
        n = int.from_bytes(d[p+2:p+4], "big")
        p += 4
        if p+n > limit:
            return None
        if typ == 0 and n >= 5:
            q = p+2
            if q+3 <= p+n and d[q] == 0:
                name_len = int.from_bytes(d[q+1:q+3], "big")
                if q+3+name_len <= p+n:
                    return d[q+3:q+3+name_len].decode("ascii", "replace")
        p += n
    return None


def make_hello(name):
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    payload = outgoing.read()
    assert len(payload) >= 9 and payload[0] == 22
    assert int.from_bytes(payload[3:5], "big")+5 == len(payload)
    assert sni_from_hello(payload) == name, (name, sni_from_hello(payload))
    return payload


def client():
    print("CLIENT_TOTAL_FAMILIES", len(FAMILIES), "SUBDOMAINS", len(SUBDOMAINS),
          "EXACT_CDNS", len(EXACT_CDNS), "HOST_COUNT", len(HOSTS), flush=True)
    for idx, host in enumerate(HOSTS, 1):
        hello = make_hello(host)
        print("CASE_START", idx, host, "UTC", utc(), "HELLO_TOTAL", len(hello), flush=True)
        try:
            with socket.create_connection((FOREIGN, 443), timeout=5) as s:
                s.settimeout(.45)
                s.sendall(hello)
                print("CLIENT_SENT", idx, host, "HELLO_BYTES", len(hello), "UTC", utc(), flush=True)
                try:
                    reply = s.recv(300)
                    print("CLIENT_REPLY", idx, host, "BYTES", len(reply),
                          "TYPE", reply[0] if reply else "EOF", flush=True)
                except socket.timeout:
                    print("CLIENT_REPLY", idx, host, "NO_RESPONSE_IN_450MS", flush=True)
        except OSError as e:
            print("CLIENT_CONNECT_OR_SEND_FAILURE", idx, host, type(e).__name__, flush=True)
        time.sleep(.18)
    print("CLIENT_COMPLETE", utc(), flush=True)


def observe(runner_ip, seconds):
    assert runner_ip != FOREIGN
    socket.inet_aton(runner_ip)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    raw.settimeout(.2)
    flows = {}
    seen = collections.Counter()
    end = time.monotonic() + seconds
    print("OBS_READY_FOREIGN89", utc(), "SEC", seconds, flush=True)
    while time.monotonic() < end:
        try:
            ip, metadata = raw.recvfrom(12288)
        except socket.timeout:
            continue
        if len(ip) < 40 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        if ihl < 20 or len(ip) < ihl+20:
            continue
        if struct.unpack_from("!H", ip, 6)[0] & 0x3fff:
            continue
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if src != runner_ip or dst != FOREIGN:
            continue
        tcp = ip[ihl:]
        sport, dport = struct.unpack_from("!HH", tcp)
        if dport != 443:
            continue
        off = (tcp[12] >> 4) * 4
        if off < 20 or off > len(tcp):
            continue
        flags = tcp[13]
        seq = struct.unpack_from("!I", tcp, 4)[0]
        state = flows.setdefault(sport, {
            "base": None, "parts": {}, "record_size": None,
            "complete": False, "first": utc(), "packets": 0,
            "received_bytes": 0, "retrans": 0, "iface": metadata[0],
        })
        state["packets"] += 1
        if flags & 2:
            state["base"] = (seq+1) & 0xffffffff
            seen["syn"] += 1
        body = tcp[off:]
        if not body:
            continue
        state["received_bytes"] += len(body)
        if state["base"] is None:
            state["base"] = seq
        delta = (seq-state["base"]) & 0xffffffff
        if delta > 10000:
            continue
        if delta in state["parts"]:
            state["retrans"] += 1
        else:
            state["parts"][delta] = body
        data = bytearray()
        for pos, seg in sorted(state["parts"].items()):
            if pos > len(data):
                break
            overlap = max(0, len(data)-pos)
            if overlap < len(seg):
                data.extend(seg[overlap:])
        if len(data) >= 5 and state["record_size"] is None and data[0] == 22:
            size = int.from_bytes(data[3:5], "big")+5
            if 9 <= size <= 8192:
                state["record_size"] = size
        need = state["record_size"]
        if need and len(data) >= need and not state["complete"]:
            state["complete"] = True
            hostname = sni_from_hello(bytes(data[:need]))
            state["host"] = hostname
            state["contiguous_bytes"] = len(data)
            print("ARRIVED_FULL", hostname or "SNI_PARSE_FAILED", "RECORD", need,
                  "SEGMENTS", len(state["parts"]), "IFACE", state["iface"],
                  "UTC", utc(), flush=True)
    raw.close()
    print("OBS_FINISHED", utc(), "FLOWS", len(flows), "SYN", seen["syn"], flush=True)
    full_hosts = set()
    for port, st in flows.items():
        if st["complete"]:
            if st.get("host"):
                full_hosts.add(st["host"])
            continue
        data = bytearray()
        for pos, seg in sorted(st["parts"].items()):
            if pos > len(data):
                break
            overlap = max(0, len(data)-pos)
            if overlap < len(seg):
                data.extend(seg[overlap:])
        print("INCOMPLETE_FLOW", "RECORD_EXPECTED", st["record_size"] or "UNKNOWN",
              "CONTIGUOUS", len(data), "SEGMENTS", len(st["parts"]),
              "PACKETS", st["packets"], "IFACE", st["iface"], flush=True)
    print("FULL_UNIQUE_HOSTS", len(full_hosts), flush=True)
    for h in HOSTS:
        print("HOST_RESULT", h, "FULL" if h in full_hosts else "NOT_OBSERVED_FULL", flush=True)
    print("NO_SERVER_MUTATIONS=true", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "observe":
        observe(sys.argv[2], int(sys.argv[3]))
    elif sys.argv[1] == "client":
        client()
    elif sys.argv[1] == "selftest":
        for h in HOSTS:
            assert sni_from_hello(make_hello(h)) == h
        assert len(FAMILIES) == 17 and len(EXACT_CDNS) == 3
        print("SELFTEST_OK", len(HOSTS))
    else:
        raise SystemExit("usage: client | observe RUNNER_IP SECONDS | selftest")
