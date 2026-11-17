#!/usr/bin/env python3
"""Read-only cross-leg TCP metadata diagnostic for DE89.

Executed from GitHub Actions through stdin on DE89. No persistent files and
no TLS payload, SNI or client addresses are printed.
"""
import collections
import hashlib
import os
import re
import secrets
import socket
import subprocess
import sys
import time

PUBLIC = "89.125.90.101"
LOCAL = "127.0.0.1"
REMOTE_SOURCE = os.environ.get("SSH_CONNECTION", "").split()
CONTROLLER = REMOTE_SOURCE[0] if REMOTE_SOURCE else ""

def run(argv, timeout=10):
    try:
        return subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    except Exception:
        return None

def audit():
    print("TLS_PATH_AUDIT_UTC=" + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), flush=True)
    for unit in ("nginx", "mnebydns-googlepilot", "mnebydns-dot"):
        x=run(["systemctl","is-active",unit])
        print("SERVICE_"+unit+"="+(x.stdout.strip() if x and x.returncode==0 else "UNKNOWN_OR_INACTIVE"),flush=True)
    s=run(["ss","-Hlnpt","( sport = :443 or sport = :15449 or sport = :853 )"])
    if s:
        for line in s.stdout.splitlines():
            parts=line.split()
            if len(parts)>=4:print("TCP_LISTENER="+parts[3],flush=True)
    ip4=run(["ip","-4","-o","addr","show"])
    if not ip4 or PUBLIC not in ip4.stdout:
        print("DIAG_PUBLIC_IP_NOT_LOCAL=true", flush=True)
        sys.exit(3)
    conf=run(["nginx","-T"],timeout=15)
    if conf and conf.returncode==0:
        text=conf.stdout
        print("NGINX_CONFIG_SYNTAX=PASS",flush=True)
        print("NGINX_REFERENCE_15449="+str("15449" in text),flush=True)
        print("NGINX_REFERENCE_YOUTUBEI="+str("youtubei.googleapis.com" in text),flush=True)
        print("NGINX_REFERENCE_NFQUEUE="+str("NFQUEUE" in text),flush=True)
    else:
        print("NGINX_CONFIG_SYNTAX=FAIL_OR_UNREADABLE",flush=True)
    # No firewall rule text is printed. This is only a namespace-wide count.
    for mode,cmd in (("IPTABLES",["iptables-save"]),("NFT",["nft","-a","list","ruleset"])):
        x=run(cmd,timeout=12)
        if not x or x.returncode!=0:
            print("FIREWALL_"+mode+"_READ=UNAVAILABLE",flush=True)
            continue
        ls=x.stdout.splitlines()
        count=lambda needle:sum(needle.lower() in line.lower() for line in ls)
        print("FIREWALL_"+mode+"_NFQUEUE_RULE_COUNT="+str(count("NFQUEUE")),flush=True)
        print("FIREWALL_"+mode+"_TPROXY_RULE_COUNT="+str(count("TPROXY")),flush=True)
        print("FIREWALL_"+mode+"_443_RULE_LINES="+str(count("443")),flush=True)
    print("CONTROL_ORIGIN_IDENTIFIED="+str(bool(CONTROLLER)),flush=True)

def trace():
    if os.geteuid()!=0 or not CONTROLLER:
        print("TRACE_MISSING_ROOT_OR_CONTROL_ORIGIN=true",flush=True)
        sys.exit(4)
    cmd=["timeout","40","tcpdump","-i","any","-nn","-tt","-l","-s","96","-c","60000","tcp and (port 443 or port 15449)"]
    parser=re.compile(r"^\s*([\d.]+)\s+(?:\S+\s+)?(?:(?:In|Out)\s+)?IP\s+([\d.]+)\.(\d+)\s+>\s+([\d.]+)\.(\d+):.*?Flags\s+\[([^\]]+)\].*?\blength\s+(\d+)")
    print("PATH_TRACE_ARMED_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    print("PATH_TRACE_MAX_SECONDS=40",flush=True)
    proc=subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    totals=collections.Counter()
    control=collections.Counter()
    per_sec=collections.defaultdict(collections.Counter)
    raw=0
    bad=0
    firstbad=""
    unique=set()
    salt=secrets.token_bytes(32)
    started=time.monotonic()
    try:
        for line in proc.stdout:
            raw+=1
            m=parser.match(line)
            if not m:
                bad+=1
                if not firstbad:
                    # Never print packet content or source address.
                    firstbad="IP6" if "IP6" in line else ("LINKTYPE" if " IP " in line else "OTHER")
                continue
            _,src,sp,dst,dp,flags,sz=m.groups()
            sp=int(sp);dp=int(dp);sz=int(sz)
            if dp==443 and dst==PUBLIC:
                leg="PUBLIC_INGRESS"
                peer=(src,sp)
            elif sp==443 and src==PUBLIC:
                leg="PUBLIC_RETURN"
                peer=(dst,dp)
            elif dp==15449 and dst==LOCAL:
                leg="PILOT_IN"
                peer=(src,sp)
            elif sp==15449 and src==LOCAL:
                leg="PILOT_RETURN"
                peer=(dst,dp)
            elif dp==443:
                leg="UPSTREAM_OUT"
                peer=(src,sp,dst,dp)
            elif sp==443:
                leg="UPSTREAM_RETURN"
                peer=(dst,dp,src,sp)
            else:
                leg="OTHER"
                peer=(src,sp,dst,dp)
            suffix=("_PAYLOAD" if sz>0 else "_CTRL")
            totals[leg+suffix]+=1
            totals[leg+"_BYTES"]+=sz
            sec=int(time.monotonic()-started)
            per_sec[sec][leg+suffix]+=1
            if src==CONTROLLER or dst==CONTROLLER:
                control[leg+suffix]+=1
                control[leg+"_BYTES"]+=sz
            if leg in ("PUBLIC_INGRESS","PUBLIC_RETURN","PILOT_IN","PILOT_RETURN"):
                unique.add((leg,hashlib.sha256(salt+repr(peer).encode()).digest()[:8]))
    finally:
        proc.wait(timeout=8)
    err=proc.stderr.read()
    print("PATH_TRACE_END_UTC="+time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),flush=True)
    print("PATH_TRACE_RAW_LINES="+str(raw),flush=True)
    print("PATH_TRACE_PARSED_IPV4="+str(sum(v for k,v in totals.items() if k.endswith(("_PAYLOAD","_CTRL")))),flush=True)
    print("PATH_TRACE_UNPARSED_LINES="+str(bad),flush=True)
    print("PATH_TRACE_UNPARSED_FORMAT="+firstbad,flush=True)
    print("PATH_TRACE_TCPDUMP_EXIT="+str(proc.returncode),flush=True)
    for label in sorted(totals):
        print("PATH_"+label+"="+str(totals[label]),flush=True)
    for label in sorted(control):
        print("CONTROL_"+label+"="+str(control[label]),flush=True)
    print("PATH_DISTINCT_FLOW_LEGS="+str(len(unique)),flush=True)
    # Time buckets allow correlation of the deterministic runner probes
    # to both the outside interface and GooglePilot loopback.
    for sec in sorted(per_sec):
        data=per_sec[sec]
        if sec>30:continue
        main={x:data[x] for x in ("PUBLIC_INGRESS_PAYLOAD","PUBLIC_RETURN_PAYLOAD","PILOT_IN_PAYLOAD","PILOT_RETURN_PAYLOAD","UPSTREAM_OUT_PAYLOAD","UPSTREAM_RETURN_PAYLOAD") if data.get(x)}
        if main:print("PATH_SECOND="+str(sec)+" LEGS="+str(main).replace(" ",""),flush=True)
    print("PATH_TRACE_NO_CONFIG_MODIFICATIONS=true",flush=True)
    if not raw or totals["PUBLIC_INGRESS_PAYLOAD"]==0 or totals["PUBLIC_RETURN_PAYLOAD"]==0:
        print("PATH_TRACE_CONTROL_NOT_CONFIRMED=true",flush=True)
        sys.exit(5)
    print("PATH_TRACE_PUBLIC_BOTH_DIRECTIONS_OBSERVED=PASS",flush=True)
if __name__=="__main__":
    audit()
    trace()
