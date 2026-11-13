#!/usr/bin/env python3
"""Compare MNEBYDNS ingress route choices without changing any production state.

Tests real TCP, verified TLS original-SNI, DoT over multiple RU/DE paths;
discovers current listener ownership and WireGuard reachability. Never edits
Nginx, WireGuard, CoreDNS, DNS records, firewall or customer credentials.
Does not collect traffic payloads, client addresses or secret material.
"""
from __future__ import annotations
from collections import Counter
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import ssl
import statistics
import subprocess
import sys
import time
import re

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"route-choice-results"
SSHKEYS=ROOT/"ops/mnebydns-owner-ssh-known_hosts"
RU="188.120.254.223"
DE="89.125.90.101"
WG_DE="10.66.77.1"
WG_RU="10.66.77.2"
HOSTS=("claude.ai","gemini.google.com","www.youtube.com")
SNI_DNS="dns.mnebyvpn.site"

def percentile(values,p):
    if not values:return None
    s=sorted(values)
    return round(s[max(0,min(len(s)-1,math.ceil(len(s)*p/100)-1))],1)

def tcptest(ip,port,n=8,timeout=2.5):
    values=[];fail=Counter()
    for _ in range(n):
        t=time.monotonic()
        try:
            with socket.create_connection((ip,port),timeout=timeout):pass
            values.append((time.monotonic()-t)*1000)
        except OSError as e:fail[type(e).__name__]+=1
    return dict(n=n,success=len(values),errors=dict(fail),p50_ms=percentile(values,50),
                p95_ms=percentile(values,95),slow_1s=sum(x>1000 for x in values))

def tlstest(ip,port,host,n=4,timeout=4.0):
    vals=[];fail=Counter()
    ctx=ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    for _ in range(n):
        t=time.monotonic()
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                sock.settimeout(timeout)
                with ctx.wrap_socket(sock,server_hostname=host) as tls:
                    if not tls.getpeercert():raise RuntimeError("CERT_UNVERIFIED")
                    vals.append((time.monotonic()-t)*1000)
        except Exception as ex:fail[type(ex).__name__]+=1
    return dict(n=n,tls_ok=len(vals),errors=dict(fail),
                p50_ms=percentile(vals,50),p95_ms=percentile(vals,95),
                slow_1s=sum(x>1000 for x in vals))

def inspect_node(role):
    def cmd(argv):
        try:
            r=subprocess.run(argv,capture_output=True,text=True,timeout=6)
            return r.stdout if r.returncode==0 else ""
        except (OSError,subprocess.TimeoutExpired):
            return ""
    data={"role":role}
    ipraw=cmd(["ip","-j","-4","addr","show"])
    interfaces={}
    try:
        parsed=json.loads(ipraw)
        for item in parsed:
            name=item.get("ifname","")
            addrs=item.get("addr_info",[])
            public=sum(1 for addr in addrs if addr.get("scope")=="global" and
               not (str(addr.get("local","")).startswith(("10.","172.","192.168.","127."))))
            if name in ("tg-relay","wg0") or public:
                interfaces[name]=dict(public_ipv4_count=public,
                                      wireguard_address_expected=any(a.get("local") ==
                                          (WG_RU if role=="ru" else WG_DE) for a in addrs))
    except (ValueError,TypeError):
        pass
    data["interfaces"]=interfaces
    listener_raw=cmd(["ss","-H","-lntp"])
    ports={}
    for port in (443,8443,853,8853):
        matches=[]
        for line in listener_raw.splitlines():
            parts=line.split()
            if len(parts)<5:continue
            bind=parts[3]
            if not bind.endswith(":"+str(port)):continue
            prog="unknown"
            m=re.search(r'users:\(\("([^"]+)"',line)
            if m:prog=m.group(1)
            matches.append(dict(bind="loopback" if bind.startswith(("127.","[::1]")) else
                                "non_loopback",program=prog,
                                backlog=parts[2] if len(parts)>2 else None))
        ports[str(port)]=matches
    data["tcp_listener_summary"]=ports
    data["wg_expected"]={
        "interface_present":bool(cmd(["ip","-o","link","show","tg-relay"])),
        "configured_peer_count":len(cmd(["wg","show","tg-relay","peers"]).split()),
        "handshake_recent_10min":False
    }
    peer_handshakes=cmd(["wg","show","tg-relay","latest-handshakes"])
    if peer_handshakes:
        now=int(time.time())
        data["wg_expected"]["handshake_recent_10min"]=any(
            (len(x.split())==2 and x.split()[1].isdigit() and
             0<now-int(x.split()[1])<600) for x in peer_handshakes.splitlines())
    data["nginx_ok"]=bool(cmd(["nginx","-t"])) or "syntax is ok" in cmd(["nginx","-t"])
    # nginx -t outputs status to stderr, not stdout, use explicit return code.
    try:
        data["nginx_ok"]=subprocess.run(["nginx","-t"],capture_output=True,
                                          timeout=7).returncode==0
    except (OSError,subprocess.TimeoutExpired):data["nginx_ok"]=False
    services={}
    for name in ("nginx","mnebydns-dot.service","mnebydns-googlepilot.service",
                 "wg-quick@tg-relay.service"):
        v=cmd(["systemctl","is-active",name]).strip()
        services[name]=v or "unknown"
    data["services"]=services
    return data

def measure(role):
    d={"role":role,"timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
       "system":inspect_node(role),"tcp":{},"tls":{}}
    # Public 443/8443/853 plus existing WG address: no new DNS or port.
    for key,ip,port in (
        ("de_public_443",DE,443),("de_public_8443",DE,8443),
        ("de_public_853",DE,853),("ru_public_443",RU,443),
        ("ru_public_853",RU,853),("de_wg_443",WG_DE,443),
        ("de_wg_853",WG_DE,853),("de_wg_8443",WG_DE,8443),
        ("ru_wg_443",WG_RU,443)):
        # Expected internal network unreachable from GitHub. Only two VPS do WG.
        d["tcp"][key]=tcptest(ip,port,n=7,timeout=2.3)
    # TLS checks answer whether plaintext SNI survives to correct service;
    # TCP-only success must never be reported as SmartDNS readiness.
    for key,ip,port,name in (
        ("de_public_443_claude",DE,443,"claude.ai"),
        ("de_wg_443_claude",WG_DE,443,"claude.ai"),
        ("de_public_443_gemini",DE,443,"gemini.google.com"),
        ("de_wg_443_gemini",WG_DE,443,"gemini.google.com"),
        ("ru_public_443_own_site",RU,443,"mnebyvpn.site"),
        ("ru_public_443_claude",RU,443,"claude.ai"),
        ("ru_public_853_dot",RU,853,SNI_DNS),
        ("de_public_853_dot",DE,853,SNI_DNS),
        ("de_wg_853_dot",WG_DE,853,SNI_DNS)):
        d["tls"][key]=tlstest(ip,port,name,n=3,timeout=3.2)
    return d

def remote(role):
    if role not in ("ru","de"):raise ValueError("Invalid node")
    secret=os.environ.get("RU_PASS" if role=="ru" else "DE_PASS")
    if not SSHKEYS.is_file() or not secret:raise RuntimeError("Pinned SSH auth missing")
    env=os.environ.copy();env["SSHPASS"]=secret
    host=RU if role=="ru" else DE
    args=["sshpass","-e","ssh","-T","-o","ConnectTimeout=10","-o",
          "StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
          "-o","UserKnownHostsFile="+str(SSHKEYS),"-o","GlobalKnownHostsFile=/dev/null",
          "-o","UpdateHostKeys=no","-o","LogLevel=ERROR",
          "root@"+host,"python3","-","--remote",role]
    p=subprocess.run(args,input=Path(__file__).read_bytes(),capture_output=True,
                     env=env,timeout=210)
    if p.returncode:
        raise RuntimeError("probe_"+role+"_failed rc="+str(p.returncode)+
                           " stderr_tail="+p.stderr.decode("utf-8","replace")[-160:])
    j=json.loads(p.stdout)
    if j.get("role")!=role:raise RuntimeError("Incorrect vantage")
    return j

def runner():
    d={"role":"runner","timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
       "tcp":{},"tls":{}}
    for key,ip,port in (
        ("de_public_443",DE,443),("de_public_8443",DE,8443),
        ("de_public_853",DE,853),("ru_public_443",RU,443),
        ("ru_public_853",RU,853)):
        d["tcp"][key]=tcptest(ip,port,n=5,timeout=2.5)
    for key,ip,port,name in (
        ("de_public_443_claude",DE,443,"claude.ai"),
        ("ru_public_443_own_site",RU,443,"mnebyvpn.site"),
        ("ru_public_443_claude",RU,443,"claude.ai"),
        ("ru_public_853_dot",RU,853,SNI_DNS)):
        d["tls"][key]=tlstest(ip,port,name,n=2,timeout=3.0)
    return d

def self_test():
    assert percentile([1,2,3,4],50)==2
    assert percentile([1,2,3,4],95)==4
    assert len(set((RU,DE,WG_RU,WG_DE)))==4
    assert "443" in str(443)
    print("ROUTE_CHOICE_OFFLINE_PASS=true")

def run():
    OUT.mkdir(parents=True,exist_ok=True)
    result={"created_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
      "scope":"read-only TCP + CA-verified TLS paths; not end-user phone, not application login",
      "vantages":{}}
    for role in ("ru","de"):
        try:result["vantages"][role]=remote(role)
        except Exception as ex:
            result["vantages"][role]={"error_class":type(ex).__name__,
                                      "error":str(ex)[:200]}
    result["vantages"]["runner"]=runner()
    (OUT/"metrics.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    report=["# MNEBYDNS route choice (read only)","",
        "Observation: "+result["created_at_utc"],"",
        "This is server/TCP/TLS synthetic data; no live route changed and no mobile data measured.","",
        "## TCP connect p50 and errors","",
        "| Vantage | Path | Successful | p50 ms | p95 ms | Errors |",
        "|---|---|---:|---:|---:|---|"]
    for role,r in result["vantages"].items():
        for name,entry in r.get("tcp",{}).items():
            report.append("| "+role+" | "+name+" | "+str(entry["success"])+"/"+
                          str(entry["n"])+" | "+str(entry["p50_ms"])+" | "+
                          str(entry["p95_ms"])+" | "+str(entry["errors"])+" |")
    report += ["","## CA verified TLS handshakes","",
               "| Vantage | SNI and path | TLS verified | p50 ms | Errors |",
               "|---|---|---:|---:|---|"]
    for role,r in result["vantages"].items():
        for name,entry in r.get("tls",{}).items():
            report.append("| "+role+" | "+name+" | "+str(entry["tls_ok"])+"/"+
              str(entry["n"])+" | "+str(entry["p50_ms"])+" | "+str(entry["errors"])+" |")
    report += ["","## Live listener summary / WG",""]
    for role,r in result["vantages"].items():
        if "system" in r:
            report.append("- "+role+": "+json.dumps(r["system"],sort_keys=True))
    (OUT/"report.md").write_text("\n".join(report)+"\n")
    for role,r in result["vantages"].items():
        print("ROUTE_CHOICE_"+role.upper()+"="+json.dumps(r,ensure_ascii=False,sort_keys=True),flush=True)
    print("ROUTE_CHOICE_READONLY_FINISHED=true",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif len(sys.argv)==3 and sys.argv[1]=="--remote":print(json.dumps(measure(sys.argv[2]),separators=(",",":")))
    elif sys.argv[1:]==["--run"]:run()
    else:raise SystemExit("Usage --self-test, --run, --remote ru|de")
