#!/usr/bin/env python3
"""Read-only TCP 443/853/8443 reachability and SYN backlog checks.

No HTTP, TLS payloads, production service changes or packet capture.
Only connect() and close() with bounded concurrency; counters are
aggregates and may include other traffic. Does NOT prove handset results.
"""
from __future__ import annotations
import concurrent.futures as futures
import datetime as dt
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent
SELF=Path(__file__).resolve()
OUT=ROOT/"tcp-connect-results"
EDGE="89.125.90.101"
RU="188.120.254.223"
PORTS=(443,853,8443)

def percentile(data,p):
    if not data:return None
    s=sorted(data)
    return round(s[max(0,min(len(s)-1,math.ceil(len(s)*p/100)-1))],1)

def once(ip,port,timeout=2.8):
    start=time.perf_counter()
    try:
        with socket.create_connection((ip,port),timeout=timeout):
            pass
        return {"ms":round((time.perf_counter()-start)*1000,1)}
    except OSError as ex:
        return {"error":type(ex).__name__,"ms":round((time.perf_counter()-start)*1000,1)}

def block(ip,port,num,parallel):
    if parallel>1:
        with futures.ThreadPoolExecutor(max_workers=parallel) as pool:
            result=list(pool.map(lambda _:once(ip,port),range(num)))
    else:
        result=[once(ip,port) for _ in range(num)]
    values=[x["ms"] for x in result if "error" not in x]
    errors={}
    for x in result:
        if "error" in x:
            key=x["error"];errors[key]=errors.get(key,0)+1
    return {"total":num,"success":len(values),"errors":errors,
            "p50_ms":percentile(values,50),"p95_ms":percentile(values,95),
            "over_900ms":sum(x>900 for x in values),
            "over_1900ms":sum(x>1900 for x in values),
            "max_ms":percentile(values,100)}

def snap_counters():
    values={}
    for filename in ("/proc/net/netstat","/proc/net/snmp"):
        lines=Path(filename).read_text().splitlines()
        for i in range(0,len(lines)-1,2):
            h=lines[i].split()
            v=lines[i+1].split()
            if not h or not v or h[0]!=v[0] or len(h)!=len(v):continue
            for k,n in zip(h[1:],v[1:]):
                if k in ("ListenOverflows","ListenDrops","TCPReqQFullDoCookies",
                         "TCPReqQFullDrop","TCPSynRetrans","TCPTimeouts",
                         "RetransSegs","OutRsts","InErrs","PassiveOpens","AttemptFails"):
                    try: values[h[0].rstrip(":")+"_"+k]=int(n)
                    except ValueError:pass
    return values

def observe_system():
    data={"tcp_counters":snap_counters()}
    def cmd(a):
        try:
            r=subprocess.run(a,capture_output=True,text=True,timeout=7)
            return r.stdout.strip() if r.returncode==0 else ""
        except (OSError,subprocess.TimeoutExpired):
            return ""
    ss=cmd(["ss","-H","-lnt"])
    data["listen_summary"]={}
    for port in PORTS:
        matches=[x.split() for x in ss.splitlines() if
                 any(f":{port}" in v for v in x.split()[3:5])]
        data["listen_summary"][str(port)]=[
            {"recv_queue":m[1] if len(m)>1 else "",
             "send_backlog":m[2] if len(m)>2 else ""} for m in matches[:6]]
    data["sysctl"]={}
    for key in ("net.core.somaxconn","net.ipv4.tcp_max_syn_backlog",
                "net.ipv4.tcp_syncookies","net.netfilter.nf_conntrack_count",
                "net.netfilter.nf_conntrack_max"):
        val=cmd(["sysctl","-n",key])
        if val.isdigit():data["sysctl"][key]=int(val)
    nft=cmd(["nft","-a","list","ruleset"])
    relevant=[line.strip() for line in nft.splitlines() if
        ("443" in line or "853" in line or "8443" in line) and
        any(tag in line.lower() for tag in ("drop","limit","reject","synproxy"))]
    # Never report live firewall rules or client IPs, only count and type.
    data["firewall_relevant_rules_count"]=len(relevant)
    data["firewall_limited_rules_count"]=sum("limit" in x.lower() for x in relevant)
    data["firewall_dropped_rules_count"]=sum("drop" in x.lower() for x in relevant)
    return data

def run_node(role):
    if role not in ("ru","de"):raise ValueError("Unknown node")
    report={"vantage":role,"started_at":dt.datetime.now(dt.timezone.utc).isoformat(),
            "before":observe_system(),"ports":{}}
    for port in PORTS:
        report["ports"][str(port)]={
            "serial":block(EDGE,port,num=10,parallel=1),
            "parallel8":block(EDGE,port,num=32,parallel=8)}
    report["after"]=observe_system()
    old,new=report["before"]["tcp_counters"],report["after"]["tcp_counters"]
    report["tcp_counter_delta"]={k:new.get(k,0)-n for k,n in old.items()}
    print(json.dumps(report,separators=(",",":"),ensure_ascii=False),flush=True)

def remote(role):
    file=ROOT/"ops/mnebydns-owner-ssh-known_hosts"
    secret=os.environ.get("RU_PASS" if role=="ru" else "DE_PASS")
    if not file.is_file() or not secret:raise RuntimeError("Missing pinned auth")
    env=os.environ.copy();env["SSHPASS"]=secret
    cmd=["sshpass","-e","ssh","-T","-o","ConnectTimeout=12",
         "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
         "-o","UserKnownHostsFile="+str(file),"-o","GlobalKnownHostsFile=/dev/null",
         "-o","UpdateHostKeys=no","-o","LogLevel=ERROR",
         "root@"+(RU if role=="ru" else EDGE),"python3","-","--remote",role]
    p=subprocess.run(cmd,input=SELF.read_bytes(),capture_output=True,timeout=205,env=env)
    if p.returncode:
        raise RuntimeError("SSH probe failed "+role+" exit="+str(p.returncode)+
                           " stderr_tail="+p.stderr.decode("utf-8","replace")[-150:])
    result=json.loads(p.stdout)
    if result["vantage"]!=role:raise RuntimeError("Vantage mismatch")
    return result

def self_test():
    assert percentile([1000,2,3,4],95)==1000
    assert percentile([1000,2,3,4],50)==3
    assert set(PORTS)=={443,853,8443}
    print("TCP_PATH_READONLY_SELF_TEST=PASS")

def run():
    OUT.mkdir(mode=0o700,exist_ok=True)
    response={"created_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope":"read-only TCP connect/close; no app traffic or server mutations",
              "vantages":{}}
    for role in ("ru","de"):
        try:response["vantages"][role]=remote(role)
        except Exception as ex:
            response["vantages"][role]={"error_type":type(ex).__name__,
                                         "error":str(ex)[:300]}
    runner={"vantage":"runner","ports":{}}
    for port in PORTS:
        runner["ports"][str(port)]={
            "serial":block(EDGE,port,num=5,parallel=1),
            "parallel8":block(EDGE,port,num=12,parallel=6)}
    control_ip=socket.getaddrinfo("example.org",443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
    runner["https_tcp_control"]=block(control_ip,443,num=5,parallel=1)
    runner["ru_public_443"]=block(RU,443,num=5,parallel=1)
    response["vantages"]["runner"]=runner
    (OUT/"metrics.json").write_text(json.dumps(response,ensure_ascii=False,indent=2)+"\n")
    report=["# MNEBYDNS read-only TCP port reachability 443/853/8443","",
            "Observed: "+response["created_at_utc"],"",
            "No TLS handshake or HTTP. TCP connect timings only. One runner and two VPS.",
            "Serial and 8-way parallel connection tests detect burst-related delays; no packet capture.",
            "Counters are host-wide and can reflect unrelated activity.","",
            "| Vantage | Port | Serial p50/p95 ms | Parallel p50/p95 ms | >900ms parallel | Failures |",
            "|---|---|---|---|---:|---:|"]
    for role,values in response["vantages"].items():
        for port,record in values.get("ports",{}).items():
            a,b=record["serial"],record["parallel8"]
            report.append(f"| {role} | {port} | {a['p50_ms']}/{a['p95_ms']} | "
                          f"{b['p50_ms']}/{b['p95_ms']} | {b['over_900ms']}/{b['success']} | "
                          f"{b['total']-b['success']} |")
        if "tcp_counter_delta" in values:
            report.extend(["",role+" TCP counter delta: "+json.dumps(values["tcp_counter_delta"],sort_keys=True)])
    (OUT/"report.md").write_text("\n".join(report)+"\n")
    for role,x in response["vantages"].items():
        if "ports" in x:
            print("TCP_PATH_"+role.upper()+"="+json.dumps({
                k:{"serial":v["serial"],"parallel8":v["parallel8"]}
                for k,v in x["ports"].items()},sort_keys=True),flush=True)
            if "tcp_counter_delta" in x:
                print("TCP_COUNTERS_"+role.upper()+"="+json.dumps(x["tcp_counter_delta"],sort_keys=True),flush=True)
        else:print("TCP_PATH_"+role.upper()+"_ERROR="+x.get("error_type","unknown"))
    print("TCP_PATH_READONLY_COMPLETE=true",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif sys.argv[1:]==["--run"]:run()
    elif len(sys.argv)==3 and sys.argv[1]=="--remote":run_node(sys.argv[2])
    else:raise SystemExit("usage: --self-test|--run|--remote ru|de")
