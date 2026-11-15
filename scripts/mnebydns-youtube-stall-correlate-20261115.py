#!/usr/bin/env python3
"""Read-only, bounded measurement of TCP/QUIC stalls on MNEBYDNS infrastructure.
No payload, user IP, SNI, packet file, or long-lived process is retained.
"""
import collections
import datetime as dt
import hashlib
import os
import re
import subprocess
import sys
import time

ROLE = sys.argv[1]
SALT = os.urandom(16)
START = dt.datetime.now(dt.timezone.utc)
UNIT_NAMES = [
    "mnebydns-youtube-quic-ru-43612369808",
    "mnebydns-youtube-quic-de-43612369808",
    "mnebydns-de89-public-quic-20261115",
]

def cmd(args, timeout=7):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""

def emit(name, value):
    print("VIDEO_" + ROLE + "_" + name + "=" + str(value), flush=True)

def counter_snapshot():
    data = {}
    for line in cmd(["nstat", "-az"]).splitlines():
        sp = line.split()
        if len(sp) > 1 and sp[0] in {
            "TcpRetransSegs", "TcpExtTCPSynRetrans", "TcpExtTCPTimeouts",
            "TcpExtTCPFastRetrans", "TcpExtTCPLossProbes",
            "UdpInErrors", "UdpRcvbufErrors", "UdpSndbufErrors",
            "IpOutDiscards", "TcpExtTCPBacklogDrop",
        }:
            try: data[sp[0]] = int(sp[1])
            except ValueError: pass
    return data

def wg_snapshot():
    data = cmd(["wg", "show", "tg-relay", "transfer"]).splitlines()
    values = [x.split() for x in data]
    rx = tx = 0
    for parts in values:
        if len(parts) >= 3:
            try:
                rx += int(parts[1]); tx += int(parts[2])
            except ValueError: pass
    return (rx, tx)

def token(value):
    return hashlib.sha256(SALT + value.encode()).hexdigest()[:10]

def number(body, key):
    m = re.search(r"(?<![\w])" + re.escape(key) + r":(\d+)", body)
    return int(m.group(1)) if m else 0

def sockets():
    # RFC 3449: retrans is an end-to-end counter, not proof of which hop dropped data.
    # ss -Hti: two lines per TCP socket (some kernel versions add a third diagnostic line).
    raw = cmd(["ss", "-Htin"], timeout=12)
    out = {}
    current = None
    for line in raw.splitlines():
        z = line.strip().split()
        if not z:
            continue
        if z[0] in ("ESTAB", "ESTABLISHED") and len(z) >= 5:
            local, peer = z[3], z[4]
            kind = ("INBOUND_443" if local.endswith(":443")
                    else "OUTBOUND_443" if peer.endswith(":443")
                    else "NON443")
            current = token(local + "|" + peer) if kind != "NON443" else None
            if current:
                out[current] = {"kind": kind, "localport": "443" if local.endswith(":443") else "ephemeral",
                                "peerport": "443" if peer.endswith(":443") else "ephemeral",
                                "bytes_sent": 0, "bytes_received": 0, "bytes_retrans": 0,
                                "unacked": 0, "rto": 0, "retrans": 0}
            continue
        if current and "bytes_sent:" in line:
            row = out[current]
            for x in ("bytes_sent","bytes_received","bytes_retrans","unacked","rto"):
                row[x] = number(line, x)
            # TCP retrans: count retransmits on currently outstanding segments.
            m = re.search(r"(?:^|\s)retrans:(\d+)/(\d+)",line)
            row["retrans"] = int(m.group(2)) if m else 0
            current = None
    return out

def journal():
    # Parse only aggregate counters emitted by our own UDP relay; discard messages and any addresses.
    ans = {}
    for unit in UNIT_NAMES:
        s = cmd(["journalctl","-u",unit,"--since","-1 minutes","-q","--no-pager","-o","cat"], timeout=9)
        samples = []
        for line in s.splitlines():
            if "youtube_quic_" not in line or "_active=" not in line:continue
            kv = dict((k,int(v)) for k,v in re.findall(r"\b([a-z_]+)=(\d+)\b",line))
            if "admitted" in kv and "client_tx" in kv:
                samples.append(kv)
        if samples:
            ans[unit] = samples[-1]
    return ans

def summary_socket(snap):
    sums = collections.defaultdict(lambda: collections.Counter())
    for row in snap.values():
        k = row["kind"]
        sums[k]["connections"] += 1
        for name in ("bytes_sent","bytes_received","bytes_retrans","unacked"):
            sums[k][name] += row[name]
        if row["bytes_retrans"] > 0:sums[k]["connections_with_historic_retrans"] += 1
        if row["unacked"] > 0:sums[k]["connections_with_unacked"] += 1
    return sums

def differences(a,b):
    for key in sorted(set(a)|set(b)):
        emit("KERNEL_DELTA_"+key, b.get(key,0)-a.get(key,0))

emit("UTC_START", START.isoformat())
emit("TCP_LISTENERS", sum(1 for l in cmd(["ss","-H","-ltn"]).splitlines() if ":443" in l))
for unit in UNIT_NAMES:
    x=cmd(["systemctl","is-active",unit]).strip()
    if x=="active": emit("SERVICE_"+unit,"active")
first_ker = counter_snapshot()
first_wg = wg_snapshot()
first_journal = journal()
samples = []
for i in range(5):
    z = sockets()
    samples.append(z)
    totals = summary_socket(z)
    for kind in ("INBOUND_443","OUTBOUND_443"):
        agg=totals[kind]
        emit("SAMPLE_"+str(i)+"_"+kind+"_CONNS", agg["connections"])
        emit("SAMPLE_"+str(i)+"_"+kind+"_BYTES_SENT_CUMULATIVE", agg["bytes_sent"])
        emit("SAMPLE_"+str(i)+"_"+kind+"_BYTES_RETRANS_CUMULATIVE", agg["bytes_retrans"])
    if i < 4:time.sleep(5)
# Per-connection deltas avoid treating pre-existing lifetime retransmissions as new ones.
paired=[]
for k,last in samples[-1].items():
    first=next((s[k] for s in samples[:-1] if k in s),None)
    if not first:continue
    d={name:max(0,last[name]-first[name]) for name in ("bytes_sent","bytes_received","bytes_retrans")}
    d["kind"]=last["kind"]
    d["id"]=k
    d["unacked_end"]=last["unacked"]
    if d["bytes_sent"] or d["bytes_received"] or d["bytes_retrans"]:paired.append(d)
for kind in ("INBOUND_443","OUTBOUND_443"):
    rows=[x for x in paired if x["kind"]==kind]
    emit("STABLE_"+kind+"_COUNT",len(rows))
    emit("STABLE_"+kind+"_SENT_BYTES",sum(x["bytes_sent"] for x in rows))
    emit("STABLE_"+kind+"_RETRANS_BYTES",sum(x["bytes_retrans"] for x in rows))
    emit("STABLE_"+kind+"_RECEIVED_BYTES",sum(x["bytes_received"] for x in rows))
    emit("STABLE_"+kind+"_STALLED",sum(x["bytes_sent"]<4096 and x["bytes_retrans"]>2048 for x in rows))
    for i,item in enumerate(sorted(rows,key=lambda r:(r["bytes_retrans"],r["unacked_end"]),reverse=True)[:6]):
        emit("TOP_"+kind+"_"+str(i),repr(item))
differences(first_ker,counter_snapshot())
last_wg=wg_snapshot()
emit("WG_RX_BYTES_DELTA", last_wg[0]-first_wg[0])
emit("WG_TX_BYTES_DELTA", last_wg[1]-first_wg[1])
for unit,final in journal().items():
    begin=first_journal.get(unit,{})
    keys=("admitted","rejected","expired","rx","to_upstream","upstream_rx",
          "client_tx","overflow","socket_error","emsgsize","not_youtube",
          "partial_initial","pending_expired","unreadable_initial")
    emit("QUIC_UNIT",unit)
    emit("QUIC_ACTIVE_END",final.get("active","unknown"))
    for key in keys:
        if key in final and key in begin:
            emit("QUIC_DELTA_"+key, final[key]-begin[key])
emit("UTC_END",dt.datetime.now(dt.timezone.utc).isoformat())
emit("COMPLETED","READ_ONLY")
