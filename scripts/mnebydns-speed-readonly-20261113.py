#!/usr/bin/env python3
"""Read-only, comparative SmartDNS speed and reliability measurement (RU/DE/runner).

No client keys, DNS packet capture, config writes, reboots, restarts or
production rule changes. Cold TLS vs reused DoT TLS isolates network setup
from server-side DNS work. Server inventory contains aggregates only.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
OUT = ROOT / "speed-readonly-results"
EDGE = "89.125.90.101"
RU = "188.120.254.223"
TRUST = ROOT / "ops/mnebydns-owner-ssh-known_hosts"
SNI = "dns.mnebyvpn.site"
HOSTS = ("example.org", "gemini.google.com", "claude.ai",
         "www.youtube.com", "grok.com", "www.tiktok.com",
         "cloud.oracle.com", "codebrowser.dev", "id.cisco.com")
CONTROL_HTTPS = ("gemini.google.com", "claude.ai", "www.youtube.com",
                 "cloud.oracle.com", "codebrowser.dev", "id.cisco.com")

def percentile(values, p):
    if not values:
        return None
    a = sorted(values)
    return round(a[max(0,min(len(a)-1,math.ceil(len(a)*p/100)-1))],2)

def aggregate(values, attempted, errors):
    return {"attempted":attempted, "success":len(values),
            "errors":errors, "p50_ms":percentile(values,50),
            "p95_ms":percentile(values,95), "max_ms":percentile(values,100)}

def recv_exact(conn, size):
    data = bytearray()
    while len(data)<size:
        b=conn.recv(size-len(data))
        if not b:
            raise EOFError("short DoT response")
        data.extend(b)
    return bytes(data)

def dot_packet(host):
    labels=host.split(".")
    wire=b"".join(bytes([len(x)])+x.encode("ascii") for x in labels)+b"\x00"
    qid=int.from_bytes(os.urandom(2),"big")
    return qid, struct.pack("!HHHHHH",qid,0x100,1,0,0,0)+wire+struct.pack("!HH",1,1)

def query(conn, host):
    txid,packet=dot_packet(host)
    started=time.perf_counter()
    conn.sendall(len(packet).to_bytes(2,"big")+packet)
    length=int.from_bytes(recv_exact(conn,2),"big")
    if length<12 or length>16384:
        raise ValueError("invalid DoT frame length")
    hdr=recv_exact(conn,length)[:12]
    answer_id,flags,qd,_,_,_=struct.unpack("!HHHHHH",hdr)
    if answer_id!=txid or not flags&0x8000 or qd!=1:
        raise ValueError("DoT response mismatch")
    if (flags&15)!=0:
        raise RuntimeError("DNS_RCODE_"+str(flags&15))
    return round((time.perf_counter()-started)*1000,2)

def connected(ip, hostname, timeout):
    t0=time.perf_counter()
    sock=socket.create_connection((ip,853),timeout=timeout)
    tcp=(time.perf_counter()-t0)*1000
    try:
        sock.settimeout(timeout)
        wrapped=ssl.create_default_context().wrap_socket(sock,server_hostname=hostname)
        tls=(time.perf_counter()-t0)*1000
        return wrapped,round(tcp,2),round(tls-tcp,2)
    except Exception:
        sock.close()
        raise

def dot_bench(ip, name, cold=7, warm=30, timeout=3.0):
    cold_totals, tcp_vals, tls_vals, query_vals=[],[],[],[]
    errors={}
    for i in range(cold):
        try:
            tls,tcp_ms,tls_ms=connected(ip,name,timeout)
            with tls:
                dns_ms=query(tls,HOSTS[i%len(HOSTS)])
            cold_totals.append(round(tcp_ms+tls_ms+dns_ms,2))
            tcp_vals.append(tcp_ms);tls_vals.append(tls_ms);query_vals.append(dns_ms)
        except Exception as ex:
            key=type(ex).__name__+(":"+str(ex)[:40] if isinstance(ex,RuntimeError) else "")
            errors[key]=errors.get(key,0)+1
    warm_rtt=[]
    warm_error={}
    try:
        tls,_,_=connected(ip,name,timeout)
        with tls:
            for i in range(warm):
                try:
                    warm_rtt.append(query(tls,HOSTS[i%len(HOSTS)]))
                except Exception as ex:
                    key=type(ex).__name__
                    warm_error[key]=warm_error.get(key,0)+1
                    break
    except Exception as ex:
        warm_error[type(ex).__name__]=warm_error.get(type(ex).__name__,0)+1
    return {"cold_end_to_end":aggregate(cold_totals,cold,errors),
            "cold_tcp_connect":aggregate(tcp_vals,cold,{}),
            "cold_tls_handshake":aggregate(tls_vals,cold,{}),
            "cold_dns_request":aggregate(query_vals,cold,{}),
            "warm_same_tls_request":aggregate(warm_rtt,warm,warm_error)}

def https_bench(ip,hosts):
    checks=[]
    for host in hosts:
        record={"host":host}
        started=time.perf_counter()
        try:
            with socket.create_connection((ip,443),timeout=5) as sock:
                tcp=(time.perf_counter()-started)*1000
                sock.settimeout(6)
                with ssl.create_default_context().wrap_socket(sock,server_hostname=host) as tls:
                    tls_ms=(time.perf_counter()-started)*1000-tcp
                    tls.sendall(("GET / HTTP/1.1\r\nHost: "+host+
                      "\r\nUser-Agent: MNEBYDNS-ReadOnly-Speed/1.0\r\n"+
                      "Connection: close\r\n\r\n").encode("ascii"))
                    head=tls.recv(128)
                    m=re.match(rb"HTTP/1\.[01] ([1-5][0-9]{2})\b",head)
                    record.update(tcp_ms=round(tcp,2),tls_ms=round(tls_ms,2),
                                  first_byte_ms=round((time.perf_counter()-started)*1000,2),
                                  http=int(m.group(1)) if m else None,
                                  tls_verified=bool(tls.getpeercert()))
        except Exception as ex:
            record["error"]=type(ex).__name__
        checks.append(record)
    return checks

def get_cmd(args,timeout=8):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return p.stdout.strip() if p.returncode==0 else ""
    except (OSError,subprocess.TimeoutExpired):
        return ""

def service_state(name):
    return get_cmd(["systemctl","is-active",name]) or "unknown"

def server_inventory(role):
    data={"role":role,"services":{x:service_state(x) for x in (
        "mnebydns-dot.service","nginx.service","mnebydns-googlepilot.service","xray.service")}}
    core=Path("/opt/mnebydns-dot/Corefile")
    nginx=Path("/etc/nginx/nginx.conf")
    if core.is_file():
        raw=core.read_text(encoding="utf-8",errors="replace")
        data["corefile_bytes"]=core.stat().st_size
        data["corefile_sha256"]=hashlib.sha256(core.read_bytes()).hexdigest()
        data["template_total"]=len(re.findall(r"(?m)^\s*template\s+IN\s+",raw))
        data["template_kinds"]={k:len(re.findall(r"(?m)^\s*template\s+IN\s+"+k+r"\s+",raw))
             for k in ("A","AAAA","HTTPS","SVCB","CNAME")}
        data["owner_core_blocks"]=raw.count("# BEGIN MNEBYDNS_OWNER_EXACT_")
        data["corefile_cache_blocks"]=len(re.findall(r"(?m)^\s*cache\s+\d+",raw))
    if nginx.is_file():
        raw=nginx.read_text(encoding="utf-8",errors="replace")
        data["nginx_conf_bytes"]=nginx.stat().st_size
        data["owner_nginx_blocks"]=raw.count("# BEGIN MNEBYDNS_OWNER_EXACT_")
    status=get_cmd(["systemctl","show","mnebydns-dot.service","--property=MainPID,CPUUsageNSec,MemoryCurrent,TasksCurrent,MemoryMax","--no-pager"])
    parsed={}
    for line in status.splitlines():
        if "=" in line:
            k,v=line.split("=",1)
            parsed[k]=v
    data["dot_process_counters"]=parsed
    try:
        pid=int(parsed.get("MainPID","0"))
        if pid>1:
            lines=Path(f"/proc/{pid}/status").read_text().splitlines()
            data["dot_process_status"]={k.strip():v.strip() for k,v in
                (line.split(":",1) for line in lines if ":" in line)
                if k in ("VmRSS","VmSize","Threads","FDSize")}
    except (OSError,ValueError):
        pass
    data["loadavg"]=list(os.getloadavg())
    mem=Path("/proc/meminfo").read_text().splitlines()
    data["memory_kib"]={key:int(v.strip().split()[0]) for line in mem if ":" in line
         for key,v in [line.split(":",1)] if key in ("MemTotal","MemAvailable","SwapFree")}
    journal=get_cmd(["journalctl","-u","mnebydns-dot.service","--since","-30min",
                     "-o","cat","-n","300","--no-pager"],timeout=8).lower()
    data["recent_dot_log_totals"]={name:journal.count(name) for name in
        ("servfail","timeout","permission denied","error","failed","start request repeated")}
    data["listener_853_count"]=sum("853" in line for line in
        get_cmd(["ss","-H","-lnt","sport = :853"]).splitlines())
    data["wireguard_interfaces"]=len(get_cmd(["wg","show","interfaces"]).split())
    return data

def node(role):
    # Never output host/account identifiers from journal or connection state.
    result={"vantage":role,"time_utc":dt.datetime.now(dt.timezone.utc).isoformat()}
    result["inventory"]=server_inventory(role)
    result["direct_dot_to_foreign"]=dot_bench(EDGE,SNI,cold=7,warm=30,timeout=2.7)
    if role=="de":
        result["cloudflare_reference"]=dot_bench("1.1.1.1","cloudflare-dns.com",cold=7,warm=30,timeout=2.7)
    result["https_via_foreign_public"]=https_bench(EDGE,CONTROL_HTTPS)
    print(json.dumps(result,ensure_ascii=False,separators=(",",":")))

def remote(role):
    if role not in ("ru","de"):raise ValueError("Invalid node")
    secret=os.environ.get("RU_PASS" if role=="ru" else "DE_PASS")
    if not secret:raise RuntimeError("Missing authorized SSH secret")
    if not TRUST.is_file():raise RuntimeError("Missing pinned SSH host key file")
    env=os.environ.copy()
    env["SSHPASS"]=secret
    host=RU if role=="ru" else EDGE
    cmd=["sshpass","-e","ssh","-T","-o","ConnectTimeout=12",
         "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
         "-o","UserKnownHostsFile="+str(TRUST),"-o","GlobalKnownHostsFile=/dev/null",
         "-o","UpdateHostKeys=no","-o","LogLevel=ERROR","root@"+host,
         "python3","-","--remote",role]
    proc=subprocess.run(cmd,input=SELF.read_bytes(),capture_output=True,timeout=190,env=env)
    if proc.returncode:
        raise RuntimeError(role+" SSH/read-only probe failed with exit "+str(proc.returncode)
                           +": "+proc.stderr.decode("utf-8","replace")[-300:])
    raw=proc.stdout.decode("utf-8","replace").strip()
    data=json.loads(raw)
    if data.get("vantage")!=role:raise RuntimeError("Remote vantage mismatch")
    return data

def self_test():
    assert percentile([1,2,3,4,100],95)==100
    assert percentile([100,2,3,4,1],50)==3
    assert len(HOSTS)>5 and len(CONTROL_HTTPS)>3
    q,p=dot_packet("example.org")
    assert len(p)>20 and p[2:4]==b"\x01\x00"
    print("MNEBYDNS_SPEED_READONLY_OFFLINE=PASS")

def run():
    OUT.mkdir(mode=0o700,exist_ok=True)
    report={"created_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
            "scope":"read-only server and external synthetic probes; no end-user phone observed",
            "vantages":{}}
    report["vantages"]["runner"]={
        "vantage":"runner",
        "direct_dot_to_foreign":dot_bench(EDGE,SNI,cold=7,warm=30,timeout=3.4),
        "cloudflare_reference":dot_bench("1.1.1.1","cloudflare-dns.com",cold=7,warm=30,timeout=3.4),
        "https_via_foreign_public":https_bench(EDGE,CONTROL_HTTPS)}
    for role in ("de","ru"):
        try:report["vantages"][role]=remote(role)
        except Exception as ex:
            report["vantages"][role]={"error_type":type(ex).__name__,
                        "error":str(ex)[:350]}
    (OUT/"metrics.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    doc=["# MNEBYDNS — read-only speed and stability comparison","",
         "Run: "+report["created_at_utc"],"",
         "Synthetic probes, NOT an end-user device or confirmation of all websites.",
         "No production changes. Cold DoT = new verified TCP+TLS, warm = same reusable TLS connection.",
         "p95 is computed from observed sample (not an SLA).","",
         "| Vantage | Foreign DoT cold p50/p95 ms | DoT warm p50/p95 ms | Cold failures |",
         "|---|---:|---:|---:|"]
    for role,d in report["vantages"].items():
        if "error_type" in d:
            doc.append("| "+role+" | ERROR: "+d["error_type"]+" | - | - |")
            continue
        b=d["direct_dot_to_foreign"]
        cold=b["cold_end_to_end"];warm=b["warm_same_tls_request"]
        doc.append(f"| {role} | {cold['p50_ms']} / {cold['p95_ms']} | "+
                   f"{warm['p50_ms']} / {warm['p95_ms']} | "+
                   f"{cold['attempted']-cold['success']} / {cold['attempted']} |")
    for role,d in report["vantages"].items():
        if "inventory" in d:
            inv=d["inventory"]
            doc.extend(["",f"## {role} infrastructure",
               f"Services: {inv.get('services')}",
               f"CoreDNS templates: {inv.get('template_total')}"+
                    f", owner route blocks: {inv.get('owner_core_blocks')}"+
                    f", bytes: {inv.get('corefile_bytes')}",
               f"DoT process counters: {inv.get('dot_process_counters')}",
               f"Available KiB: {inv.get('memory_kib',{}).get('MemAvailable')}",
               f"DoT log error aggregates: {inv.get('recent_dot_log_totals')}"])
    (OUT/"report.md").write_text("\n".join(doc)+"\n")
    for role,data in report["vantages"].items():
        if "error_type" in data:
            print("DNS_SPEED_"+role.upper()+"_ERROR="+data["error_type"])
        else:
            b=data["direct_dot_to_foreign"]
            print("DNS_SPEED_"+role.upper()+"="+json.dumps({
                "cold":b["cold_end_to_end"],"warm":b["warm_same_tls_request"],
                "reference":data.get("cloudflare_reference",{}).get("cold_end_to_end"),
                "core_templates":data.get("inventory",{}).get("template_total"),
                "services":data.get("inventory",{}).get("services"),
                "recent_errors":data.get("inventory",{}).get("recent_dot_log_totals")
            },ensure_ascii=False,sort_keys=True),flush=True)
    print("MNEBYDNS_SPEED_READONLY_FINISHED=true",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif len(sys.argv)==3 and sys.argv[1]=="--remote":node(sys.argv[2])
    elif sys.argv[1:]==["--run"]:run()
    else:raise SystemExit("usage: --self-test | --run | --remote ru|de")
