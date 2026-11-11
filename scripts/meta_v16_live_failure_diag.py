#!/usr/bin/env python3
"""Read-only fault isolation of active v16 phone canary. Suppress peer identities."""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time

ROOT=Path("/var/lib/mneby-meta-v15-routes")
STATE=Path("/var/lib/mneby-meta-v15-controller")
EDGE="89.125.90.101"

def run(args, *, timeout=7):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def emit(key,value):
    print("meta_v16_diag_"+key+"="+str(value).replace("\n","")[:150],flush=True)

def count_nft():
    result=run(["nft","-j","list","table","inet","mneby_meta_v15"])
    if result.returncode:
        emit("nft_table","ABSENT_OR_FAILED")
        return
    data=json.loads(result.stdout)
    emit("nft_table","PRESENT")
    rules=[x["rule"] for x in data.get("nftables",[]) if "rule" in x]
    for rule in rules:
        chain=rule.get("chain","")
        vals=[e["counter"] for e in rule.get("expr",[]) if "counter" in e]
        if chain in ("pre","out"):
            emit("nft_"+chain+"_packets",sum(x.get("packets",0) for x in vals))
            emit("nft_"+chain+"_bytes",sum(x.get("bytes",0) for x in vals))

def capture_stats():
    # Privately inspect only aggregate conn count, never peer addresses.
    try:
        result=run(["ss","-H","-nt","state","established"],timeout=5)
        if result.returncode:
            emit("established_sockets","UNKNOWN")
            return
        lines=result.stdout.splitlines()
        emit("local_proxy_established_count",sum(1 for x in lines if ":18443 " in x or ":18443\t" in x))
        emit("all_established_sockets_count",len(lines))
    except Exception:
        emit("established_sockets","ERROR")

def status():
    if ROOT.joinpath("ready_epoch").exists():
        start=int(ROOT.joinpath("ready_epoch").read_text().strip())
        now=int(time.time())
        emit("ready",True)
        emit("elapsed_seconds",now-start)
        emit("remaining_seconds",max(0,start+1800-now))
    else:
        emit("ready",False)
    emit("rollback_started",STATE.joinpath("cleanup-started").exists())
    for unit in ("mneby-meta-v15-proxy.service",
                 "nginx.service","mnebydns-dot.service",
                 "mneby-meta-v15-cleanup.timer",
                 "mneby-meta-v15-route-watchdog.timer"):
        p=run(["systemctl","is-active",unit],timeout=6)
        emit("service_"+unit.split(".")[0].replace("-","_"),p.stdout.strip() or "unknown")
    count_nft()
    capture_stats()
    if ROOT.joinpath("core.original").exists() and ROOT.joinpath("core.candidate").exists():
        src=Path("/opt/mnebydns-dot/Corefile").read_bytes()
        orig=ROOT.joinpath("core.original").read_bytes()
        cand=ROOT.joinpath("core.candidate").read_bytes()
        emit("live_coredns_state","EXPERIMENT" if src==cand else ("BASELINE" if src==orig else "UNKNOWN"))
    if ROOT.joinpath("nginx.original").exists() and ROOT.joinpath("nginx.candidate").exists():
        src=Path("/etc/nginx/nginx.conf").read_bytes()
        orig=ROOT.joinpath("nginx.original").read_bytes()
        cand=ROOT.joinpath("nginx.candidate").read_bytes()
        emit("live_nginx_state","EXPERIMENT" if src==cand else ("BASELINE" if src==orig else "UNKNOWN"))

def dns():
    import mnebydns_iglite_dns_wire_checks as checks
    for host in ("i.instagram.com","iglite-z.instagram.com","www.instagram.com",
                 "www.youtube.com"):
        try:
            answer={}
            for t in ("A","AAAA","HTTPS"):
                # non-Meta is allowed to return a different address.
                result=checks.read_exact_dot_type(checks.QTYPES[t],host=host,timeout=3)
                answer[t]=result
            emit("dot_"+host.replace(".","_"),",".join(k+":"+v for k,v in answer.items()))
        except Exception as exc:
            emit("dot_"+host.replace(".","_"),type(exc).__name__)

def tcp():
    for host in ("i.instagram.com","iglite-z.instagram.com","www.youtube.com"):
        try:
            with socket.create_connection((EDGE,443),timeout=5) as sock:
                sock.settimeout(5)
                with ssl.create_default_context().wrap_socket(sock,server_hostname=host) as tls:
                    emit("tls_"+host.replace(".","_"),"VERIFIED_"+str(tls.version()))
        except Exception as exc:
            emit("tls_"+host.replace(".","_"),type(exc).__name__)

if __name__=="__main__":
    status()
    dns()
    tcp()
    emit("read_only",True)
