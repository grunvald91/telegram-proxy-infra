#!/usr/bin/env python3
"""Read-only RU IPv4 return-route and TCP listener health for test runner IP.

No packets, secrets, route changes, or raw public IP output.
"""
from __future__ import annotations
import ipaddress
import json
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
    route=command(["ip","-4","-j","route","get",peer,"from",SERVER])
    if not route or route.returncode:
        flag("ru_return_route","ERROR")
    else:
        try:
            record=json.loads(route.stdout)[0]
        except (ValueError,IndexError,KeyError):
            record={}
        dev=record.get("dev")
        src=record.get("prefsrc") or record.get("src") or record.get("from")
        flag("ru_return_route","PRESENT" if record else "UNPARSEABLE")
        flag("ru_return_route_device",dev or "UNKNOWN")
        flag("ru_return_route_source_is_public",str(src==SERVER).lower() if src else "UNKNOWN")
        flag("ru_return_route_mentions_wireguard",str(bool(dev and dev.startswith("wg"))).lower())
        flag("ru_return_route_source_field",("prefsrc" if record.get("prefsrc") else
             "src" if record.get("src") else "from" if record.get("from") else "missing"))
    unforced=command(["ip","-4","-j","route","get",peer])
    if unforced and unforced.returncode==0:
        try: unforced_record=json.loads(unforced.stdout)[0]
        except (ValueError,IndexError): unforced_record={}
        default_src=unforced_record.get("prefsrc") or unforced_record.get("src")
        flag("ru_default_return_route_device",unforced_record.get("dev","UNKNOWN"))
        flag("ru_default_return_route_source_is_public",
             str(default_src==SERVER).lower() if default_src else "UNKNOWN")
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
        flag("ru_current_synrecv_443_for_runner",sum(1 for line in ss.stdout.splitlines()
             if re.search(rf"(?:^|[^0-9]){re.escape(peer)}:",line)))
    fwmark_file=pathlib.Path("/proc/sys/net/ipv4/tcp_fwmark_accept")
    flag("ru_tcp_fwmark_accept",fwmark_file.read_text().strip() if fwmark_file.exists() else "UNKNOWN")
    mark=command(["iptables","-w","-t","mangle","-S","PREROUTING"])
    if mark and mark.returncode==0:
        flag("ru_mangle_prerouting_total",len(mark.stdout.splitlines()))
        flag("ru_mangle_prerouting_mark_count",sum(1 for line in mark.stdout.splitlines() if "-j MARK" in line))
        flag("ru_mangle_prerouting_443_mark_count",sum(1 for line in mark.stdout.splitlines() if "-j MARK" in line and "--dport 443" in line))
    flag("ru_route_observer","COMPLETE_READ_ONLY")

if __name__=="__main__":
    main()
