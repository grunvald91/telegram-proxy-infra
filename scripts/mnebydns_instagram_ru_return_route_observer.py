#!/usr/bin/env python3
"""Read-only RU IPv4 return-route and TCP listener health for test runner IP.

No packets, secrets, route changes, or raw public IP output.
"""
from __future__ import annotations
import ipaddress
import pathlib
import re
import socket
import subprocess
import sys

SERVER="188.120.254.223"

def command(args):
    try:
        return subprocess.run(args,text=True,capture_output=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None

def flag(k,value):
    print(f"{k}={value}",flush=True)

def main():
    if len(sys.argv)!=2 or not ipaddress.IPv4Address(sys.argv[1]).is_global:
        raise SystemExit("Source public IPv4 required")
    peer=sys.argv[1]
    route=command(["ip","-4","route","get",peer,"from",SERVER])
    if not route or route.returncode:
        flag("ru_return_route","ERROR")
    else:
        text=route.stdout.strip()
        dev=re.search(r"\bdev\s+(\S+)",text)
        src=re.search(r"\bsrc\s+(\S+)",text)
        flag("ru_return_route","PRESENT")
        flag("ru_return_route_device",dev.group(1) if dev else "UNKNOWN")
        flag("ru_return_route_source_is_public",str(bool(src and src.group(1)==SERVER)).lower())
        flag("ru_return_route_mentions_wireguard",str(bool(re.search(r"\bwg\d+\b",text))).lower())
    p=command(["ip","-4","rule","show"])
    if p and p.returncode==0:
        flag("ru_policy_rule_count",len(p.stdout.splitlines()))
        flag("ru_policy_fwmark_rules",sum(1 for line in p.stdout.splitlines() if "fwmark" in line))
        flag("ru_policy_iif_rules",sum(1 for line in p.stdout.splitlines() if "iif" in line))
    for key in ("TcpExtListenDrops","TcpExtListenOverflows","TcpExtTCPReqQFullDrop",
                "TcpExtSyncookiesSent","TcpExtTCPBacklogDrop"):
        p=command(["nstat","-az",key])
        if p and p.returncode==0:
            entries=[line.split() for line in p.stdout.splitlines() if line.startswith(key+" ")]
            if entries:
                try:flag("ru_nstat_"+key,int(entries[0][1]))
                except ValueError:flag("ru_nstat_"+key,"INVALID")
    ss=command(["ss","-H","-n","state","syn-recv","sport","=",":443"])
    if ss and ss.returncode==0:
        flag("ru_current_synrecv_443",len(ss.stdout.splitlines()))
    mark=command(["iptables","-w","-t","mangle","-S","PREROUTING"])
    if mark and mark.returncode==0:
        flag("ru_mangle_prerouting_total",len(mark.stdout.splitlines()))
        flag("ru_mangle_prerouting_mark_count",sum(1 for line in mark.stdout.splitlines() if "-j MARK" in line))
        flag("ru_mangle_prerouting_443_mark_count",sum(1 for line in mark.stdout.splitlines() if "-j MARK" in line and "--dport 443" in line))
    flag("ru_route_observer","COMPLETE_READ_ONLY")

if __name__=="__main__":
    main()
