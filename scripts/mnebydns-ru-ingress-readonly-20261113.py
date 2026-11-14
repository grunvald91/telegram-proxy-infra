#!/usr/bin/env python3
"""Read-only SNI/HTTPS route coverage for RU public 443 versus DE 443.

Identifies whether RU already proxies protected hostnames through its existing
WG stream map. Compares original-SNI CA-verified TLS + response status, never
trusts plain TCP connectivity. Does not log raw config or client information.
"""
from __future__ import annotations
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import statistics
import subprocess
import sys
import time
from collections import Counter

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"ru-ingress-coverage"
RU="188.120.254.223"
DE="89.125.90.101"
KNOWN=ROOT/"ops/mnebydns-owner-ssh-known_hosts"
HOSTS=(
"claude.ai","api.anthropic.com","gemini.google.com",
"www.youtube.com","grok.com","x.com","www.tiktok.com",
"cloud.oracle.com","id.cisco.com","codebrowser.dev",
"copilot.microsoft.com","community.teamviewer.com",
"account.wbgames.com","3dwarehouse.sketchup.com",
)
WG_TARGET="10.66.77.1"

def https(host,target_ip,timeout=5):
    started=time.perf_counter()
    result={"host":host,"tls_ok":False,"http":None,"tcp_ms":None,"tls_ms":None,
            "first_byte_ms":None,"error":None}
    try:
        ctx=ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        with socket.create_connection((target_ip,443),timeout=timeout) as tcp:
            tcp.settimeout(timeout)
            result["tcp_ms"]=round((time.perf_counter()-started)*1000,1)
            with ctx.wrap_socket(tcp,server_hostname=host) as tls:
                if not tls.getpeercert():raise RuntimeError("CERT_MISSING")
                result["tls_ok"]=True
                result["tls_ms"]=round((time.perf_counter()-started)*1000,1)
                tls.sendall(("GET / HTTP/1.1\r\nHost: "+host+
                    "\r\nUser-Agent: MNEBYDNS-Safe-RouteChoice/1.0\r\n"+
                    "Connection: close\r\n\r\n").encode("ascii"))
                data=tls.recv(512)
                match=re.match(rb"HTTP/1\.[01] ([1-5][0-9]{2})\b",data)
                if match:result["http"]=int(match.group(1))
                result["first_byte_ms"]=round((time.perf_counter()-started)*1000,1)
    except (OSError,RuntimeError) as ex:
        result["error"]=type(ex).__name__
    return result

def checks():
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        de=list(ex.map(lambda x:https(x,DE),HOSTS))
        ru=list(ex.map(lambda x:https(x,RU),HOSTS))
    return {"de_public_443":de,"ru_public_443":ru}

def topology():
    try:
        p=subprocess.run(["nginx","-T"],capture_output=True,text=True,timeout=10)
        raw=p.stdout if p.returncode==0 else ""
    except (OSError,subprocess.TimeoutExpired):raw=""
    # Parse only SNI router metadata and WG linkage; DO NOT publish raw maps.
    entry={}
    aliases=(
        "ssl_preread_server_name", "proxy_pass", "10.66.77.1",
        "89.125.90.101","188.120.254.223"
    )
    for marker in aliases:
        entry[marker+"_mentions"]=raw.count(marker)
    entry["nginx_config_valid"]=bool(raw)
    entry["listed_exact_hosts"]={h:bool(re.search(r"(?m)^\s*"+re.escape(h)+r"\s+\S+;",raw))
                                 for h in HOSTS}
    entry["stream_sni_maps_count"]=len(re.findall(
        r"(?m)^\s*map\s+\$ssl_preread_server_name\s+\S+\s*{",raw))
    # Redacted 443 SNI map branch outcomes (only known names).
    for h in ("claude.ai","gemini.google.com","cloud.oracle.com","codebrowser.dev"):
        exact=re.findall(r"(?m)^\s*"+re.escape(h)+r"\s+([^;\n]+);",raw)
        entry[h+"_backend_type"]=([
            "wg" if WG_TARGET in x else ("foreign_public" if DE in x else "other")
            for x in exact][:3])
    return entry

def run_node():
    result={"time_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
            "vantage":"RU VPS","topology":topology(),"https":checks()}
    print(json.dumps(result,separators=(",",":"),ensure_ascii=False),flush=True)

def remotely_run():
    secret=os.environ.get("RU_PASS")
    if not secret or not KNOWN.is_file():raise RuntimeError("RU pinned SSH unavailable")
    env=os.environ.copy();env["SSHPASS"]=secret
    cmd=["sshpass","-e","ssh","-T","-o","StrictHostKeyChecking=yes",
         "-o","HostKeyAlgorithms=ssh-ed25519","-o","UserKnownHostsFile="+str(KNOWN),
         "-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no",
         "-o","ConnectTimeout=12","-o","LogLevel=ERROR",
         "root@"+RU,"python3","-","--remote"]
    r=subprocess.run(cmd,input=Path(__file__).read_bytes(),
                     capture_output=True,env=env,timeout=210)
    if r.returncode:
        raise RuntimeError("Pinned SSH diagnostic failed rc="+str(r.returncode)+
                           " stderr_tail="+r.stderr.decode("utf-8","replace")[-240:])
    data=json.loads(r.stdout.decode())
    if data.get("vantage")!="RU VPS":raise RuntimeError("Untrusted vantage")
    return data

def render():
    OUT.mkdir(mode=0o700,exist_ok=True)
    data=remotely_run()
    paths=data["https"]
    pairs=[]
    for ru,de in zip(paths["ru_public_443"],paths["de_public_443"]):
        if ru["host"]!=de["host"]:raise RuntimeError("Mismatched host order")
        pairs.append({"host":ru["host"],"ru":ru,"de":de,
                      "ru_has_verified_tls":ru["tls_ok"],
                      "ru_http_response":ru["http"] is not None})
    outcome={"timestamp_utc":data["time_utc"],
       "topology":data["topology"],
       "ru_tls_success":sum(x["ru"]["tls_ok"] for x in pairs),
       "de_tls_success":sum(x["de"]["tls_ok"] for x in pairs),
       "ru_http_responses":sum(x["ru"]["http"] is not None for x in pairs),
       "total":len(pairs),"paths":pairs}
    (OUT/"metrics.json").write_text(json.dumps(outcome,indent=2,ensure_ascii=False)+"\n")
    report=["# RU public 443 ingress versus foreign 443","",
      "Time: "+outcome["timestamp_utc"],"",
      "Only synthetic TLS with original SNI and GET / from RU VPS; no phone test.",
      "CA validation mandatory; HTTP 403/404 can be an expected application/path response.",
      "Live configs and DNS unchanged.","",
      "## Existing RU SNI map metadata (no raw config)","",
      json.dumps(outcome["topology"],indent=2,ensure_ascii=False),
      "","## Service comparison","",
      "| Host | RU TLS | RU HTTP | RU TCP ms | RU first byte ms | DE TLS | DE HTTP | DE TCP ms | DE first byte ms |",
      "|---|---|---:|---:|---:|---|---:|---:|---:|"]
    for x in pairs:
        a,b=x["ru"],x["de"]
        report.append("| "+x["host"]+" | "+str(a["tls_ok"])+" | "+str(a["http"])+
           " | "+str(a["tcp_ms"])+" | "+str(a["first_byte_ms"])+" | "+
           str(b["tls_ok"])+" | "+str(b["http"])+" | "+str(b["tcp_ms"])+" | "+
           str(b["first_byte_ms"])+" |")
    (OUT/"report.md").write_text("\n".join(report)+"\n")
    print("RU_INGRESS_COVERAGE_SUMMARY="+json.dumps({
       "total":outcome["total"],"ru_tls_ok":outcome["ru_tls_success"],
       "ru_http_responses":outcome["ru_http_responses"],
       "de_tls_ok":outcome["de_tls_success"],
       "ru_sni_maps":data["topology"]["stream_sni_maps_count"],
       "ru_wg_mention":data["topology"]["10.66.77.1_mentions"]},sort_keys=True),flush=True)
    print("RU_INGRESS_BY_HOST="+json.dumps([
        {"host":x["host"],"ru_http":x["ru"]["http"],"ru_error":x["ru"]["error"],
         "ru_tcp_ms":x["ru"]["tcp_ms"],"ru_first_byte_ms":x["ru"]["first_byte_ms"],
         "de_http":x["de"]["http"],"de_error":x["de"]["error"],
         "de_first_byte_ms":x["de"]["first_byte_ms"]} for x in pairs
    ],sort_keys=True),flush=True)
    print("RU_INGRESS_READONLY_DONE=true",flush=True)

def self_test():
    assert len(HOSTS)==len(set(HOSTS))
    assert "claude.ai" in HOSTS and "gemini.google.com" in HOSTS
    print("RU_INGRESS_READONLY_SELF_TEST=PASS")

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif sys.argv[1:]==["--remote"]:run_node()
    elif sys.argv[1:]==["--run"]:render()
    else:raise SystemExit("usage: --self-test|--remote|--run")
