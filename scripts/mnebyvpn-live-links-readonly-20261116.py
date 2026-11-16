#!/usr/bin/env python3
"""One-shot, bounded MNEBYVPN+SmartDNS transport diagnostics.

Uses only SSH trust-pinned sessions and private WireGuard listeners, no changes
to iptables, routing, services, credentials or customer records. Measures
*infrastructure* capacity; cannot measure a specific phone's VPN bandwidth.
"""
from __future__ import annotations
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import select
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request

RU="188.120.254.223"
DE="89.125.90.101"
WG_RU="10.66.77.2"
WG_DE="10.66.77.1"
PORT=41781
SIZE=8*1024*1024
TIMEOUT=18
ROOT=Path(__file__).resolve().parent.parent
SELF=Path(__file__).resolve()
OUT=ROOT/"live-link-results"
TRUST=ROOT/"ops/mnebydns-owner-ssh-known_hosts"
SOCK_SERVICES=("xray.service","wg-quick@tg-relay.service",
               "mnebydns-dot.service","mnebydns-googlepilot.service","nginx.service")

def run_cmd(args,timeout=8):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
        return p.returncode,p.stdout.strip()
    except (OSError,subprocess.TimeoutExpired):
        return 255,""

def status(name):
    rc,s=run_cmd(["systemctl","is-active",name],timeout=4)
    return s if rc==0 else "not_active_or_absent"

def interface_stats(name):
    p=Path("/sys/class/net")/name
    if not p.exists():return {"present":False}
    d={"present":True}
    try:d["mtu"]=int((p/"mtu").read_text().strip())
    except (OSError,ValueError):pass
    for key in ("rx_bytes","tx_bytes","rx_packets","tx_packets",
                "rx_dropped","tx_dropped","rx_errors","tx_errors"):
        try:d[key]=int((p/"statistics"/key).read_text().strip())
        except (OSError,ValueError):pass
    return d

def wg_stats():
    d={"interfaces":[],"tg_relay":interface_stats("tg-relay")}
    rc,names=run_cmd(["wg","show","interfaces"])
    if rc==0:d["interfaces"]=names.split()
    rc,raw=run_cmd(["wg","show","tg-relay","latest-handshakes"])
    if rc==0:
        ages=[max(0,int(time.time())-int(line.split()[1]))
              for line in raw.splitlines()
              if len(line.split())==2 and line.split()[1].isdigit() and int(line.split()[1])>0]
        d["peer_count"]=len(raw.splitlines())
        d["youngest_handshake_age_s"]=min(ages) if ages else None
    rc,raw=run_cmd(["wg","show","tg-relay","transfer"])
    if rc==0:
        pairs=[line.split() for line in raw.splitlines()]
        good=[p for p in pairs if len(p)==3 and p[1].isdigit() and p[2].isdigit()]
        d["cumulative_peer_rx_bytes"]=sum(int(p[1]) for p in good)
        d["cumulative_peer_tx_bytes"]=sum(int(p[2]) for p in good)
    return d

def ping(host,size,n=12):
    rc,raw=run_cmd(["ping","-n","-q","-M","do","-c",str(n),"-i","0.28",
                    "-s",str(size),"-W","1",host],timeout=15)
    line=re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received,\s*([\d.]+)% packet loss",raw)
    delay=re.search(r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms",raw)
    return {"sent":int(line.group(1)) if line else None,
            "received":int(line.group(2)) if line else None,
            "loss_pct":float(line.group(3)) if line else None,
            "rtt_min_ms":float(delay.group(1)) if delay else None,
            "rtt_avg_ms":float(delay.group(2)) if delay else None,
            "rtt_max_ms":float(delay.group(3)) if delay else None,
            "rc":rc,
            "error_type":"ping_failed_or_filtered" if not line else None}

def journal_errors(name):
    try:
        p=subprocess.run(["journalctl","-q","-u",name,"--since","-30min",
                          "--no-pager","-o","cat","-n","250"],
                         capture_output=True,text=True,timeout=7)
        if p.returncode:return {"journal_available":False}
        raw=p.stdout.lower()
        return {"journal_available":True,"sample_lines":len(raw.splitlines()),
                "error_mentions":{token:raw.count(token) for token in
                ("timeout","timed out","handshake","error","failed","permission denied",
                 "broken pipe","network unreachable","servfail","connection reset")}}
    except (OSError,subprocess.TimeoutExpired):
        return {"journal_available":False}

def reference_download():
    # Controlled 1 MiB, trusted public TLS, close after exact target count.
    url="https://speed.cloudflare.com/__down?bytes=1048576"
    t=time.monotonic()
    try:
        req=urllib.request.Request(url,headers={"User-Agent":"MNEBYVPN-TransportProbe/1.0"})
        with urllib.request.urlopen(req,timeout=10) as r:
            if r.status!=200:raise RuntimeError("Non-200 download response")
            total=0
            while total<1048576:
                fragment=r.read(min(65536,1048576-total))
                if not fragment:break
                total+=len(fragment)
        elapsed=max(0.0001,time.monotonic()-t)
        return {"status":"ok" if total==1048576 else "incomplete",
                "bytes":total,"seconds":round(elapsed,3),
                "mbps":round(8*total/elapsed/1000000,2)}
    except Exception as exc:
        return {"status":"unavailable","error_class":type(exc).__name__}

def snapshot(role):
    peer=WG_DE if role=="ru" else WG_RU
    other=DE if role=="ru" else RU
    rc,route=run_cmd(["ip","-4","route","get",peer])
    result={
        "role":role,"timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
        "services":{n:status(n) for n in SOCK_SERVICES},
        "wg":wg_stats(),
        "wg_peer_route_uses_tg_relay":rc==0 and "dev tg-relay" in route,
        "ping_wg_32":ping(peer,32),
        "ping_wg_1200":ping(peer,1200),
        "ping_wg_1320":ping(peer,1320,n=8),
        "ping_public_1200":ping(other,1200),
        "direct_public_https_reference_1mib":reference_download(),
        "logs":{name:journal_errors(name) for name in
                ("xray.service","mnebydns-dot.service","mnebydns-googlepilot.service",
                 "wg-quick@tg-relay.service")}}
    return result

def private_server(role):
    bind=WG_DE if role=="de" else WG_RU
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.settimeout(12)
    s.bind((bind,PORT))
    s.listen(1)
    print("WG_RECEIVER_READY",flush=True)
    with s:
        conn,peer=s.accept()
        with conn:
            conn.settimeout(12)
            # All-zero synthetic payload: no user traffic, keys or credentials.
            remaining=SIZE
            chunk=b"\0"*65536
            while remaining>0:
                step=min(len(chunk),remaining)
                conn.sendall(chunk[:step])
                remaining-=step
    print("WG_RECEIVER_FINISHED",flush=True)

def private_client(role):
    dest=WG_DE if role=="ru" else WG_RU
    rc,route=run_cmd(["ip","-4","route","get",dest])
    if rc!=0 or "dev tg-relay" not in route:
        raise RuntimeError("WG private peer route does not use tg-relay")
    begin=time.monotonic()
    recvd=0
    with socket.create_connection((dest,PORT),timeout=8) as conn:
        conn.settimeout(12)
        while recvd<SIZE:
            data=conn.recv(min(131072,SIZE-recvd))
            if not data:break
            recvd+=len(data)
    elapsed=max(time.monotonic()-begin,0.000001)
    print(json.dumps({"direction":("DE_to_RU" if role=="ru" else "RU_to_DE"),
         "bytes":recvd,"seconds":round(elapsed,4),
         "mbps":round(recvd*8/(elapsed*1e6),2) if recvd==SIZE else None,
         "complete":recvd==SIZE},separators=(",",":")),flush=True)

def ssh_args(role):
    host=RU if role=="ru" else DE
    secret=os.environ.get("RU_PASS" if role=="ru" else "DE_PASS")
    if not secret or not TRUST.is_file():raise RuntimeError("Missing pinned SSH credentials")
    env=os.environ.copy()
    env["SSHPASS"]=secret
    return (["sshpass","-e","ssh","-T","-o","StrictHostKeyChecking=yes",
             "-o","HostKeyAlgorithms=ssh-ed25519",
             "-o","UserKnownHostsFile="+str(TRUST),
             "-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no",
             "-o","ConnectTimeout=12","-o","LogLevel=ERROR",
             "root@"+host,"python3","-","--remote"],env)

def invoke(role,action,timeout=130):
    cmd,env=ssh_args(role)
    p=subprocess.run(cmd+[action,role],input=SELF.read_bytes(),
                     capture_output=True,timeout=timeout,env=env)
    if p.returncode:
        raise RuntimeError(role+" "+action+" SSH exit "+str(p.returncode)+
                           " "+p.stderr.decode("utf-8","replace")[-100:])
    return json.loads(p.stdout)

def tunnel_direction(sender,receiver):
    cmd,env=ssh_args(sender)
    srv=subprocess.Popen(cmd+["server",sender],env=env,
                         stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        srv.stdin.write(SELF.read_bytes())
        srv.stdin.close()
        ready,_,_=select.select([srv.stdout],[],[],14)
        if not ready:raise TimeoutError("WG private receiver did not become ready")
        if srv.stdout.readline().strip()!=b"WG_RECEIVER_READY":
            raise RuntimeError("WG private receiver failed to start")
        try:
            result=invoke(receiver,"client",timeout=30)
        finally:
            try:srv.wait(timeout=20)
            except subprocess.TimeoutExpired:srv.kill()
        if srv.returncode!=0:
            raise RuntimeError("Private test sender ended with non-zero exit")
        return result
    except Exception as exc:
        return {"direction":sender+"_to_"+receiver,
                "status":"not_measured","error_class":type(exc).__name__}
    finally:
        if srv.poll() is None:srv.kill()
        try:srv.wait(timeout=3)
        except Exception:pass
        for f in (srv.stdout,srv.stderr):
            if f:f.close()

def coordinate():
    OUT.mkdir(mode=0o700,exist_ok=True)
    results={"measurement_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
             "vantage":"GitHub Runner + DE89 + RU188; NOT user mobile VPN",
             "read_only_config":True,"traffic_budget":"<=16MiB private WG + 1MiB HTTPS per node"}
    for role in ("ru","de"):
        try:results[role]=invoke(role,"snapshot",timeout=130)
        except Exception as exc:
            results[role]={"status":"failed","error_class":type(exc).__name__}
    results["wg_bulk"]=[tunnel_direction("de","ru"),tunnel_direction("ru","de")]
    (OUT/"link_metrics.json").write_text(json.dumps(results,indent=2,ensure_ascii=False)+"\n")
    # Keep important diagnostics visible even if artifact download is unavailable.
    print("MNEBYVPN_TRANSPORT_DIAGNOSTIC="+json.dumps(results,ensure_ascii=False,separators=(",",":")),flush=True)
    print("MNEBYVPN_READONLY_FINISHED=true",flush=True)

if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="--remote":
        action,role=sys.argv[2].split(":") if ":" in sys.argv[2] else ("snapshot",sys.argv[2])
        print(json.dumps(snapshot(role),separators=(",",":")))
    elif len(sys.argv)==4 and sys.argv[1]=="--remote":
        action,role=sys.argv[2:]
        if action=="snapshot":print(json.dumps(snapshot(role),separators=(",",":")))
        elif action=="server":private_server(role)
        elif action=="client":private_client(role)
        else:raise SystemExit("bad remote action")
    elif sys.argv[1:]==["--run"]:coordinate()
    elif sys.argv[1:]==["--self-test"]:
        assert SIZE==8*1024*1024 and WG_RU!=WG_DE and PORT>1024
        print("LIVE_LINK_OFFLINE_SELF_TEST=PASS")
    else:raise SystemExit("usage --run or --remote action role")
