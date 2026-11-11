#!/usr/bin/env python3
"""One-shot LOCAL-ONLY TCP Window=4 proof-of-mechanism for Instagram Lite SNI.

Test a genuine TLS ClientHello with server_name=iglite-z.instagram.com on
DE-local public-IP loopback socket. Independently rollback test-owned nft table.
No CoreDNS/Nginx config changes, production traffic or TLS payload captured.
NO claim of Android/TSPU bypass: the tests stay inside the DE host.
"""
from __future__ import annotations
import os
import pathlib
import re
import signal
import socket
import ssl
import subprocess
import sys
import time

DE="89.125.90.101"
HOST="iglite-z.instagram.com"
TABLE="mneby_ig_local_w4_20261111"
UNIT="mneby-ig-localwin4-20261111"
RULES=(f"add table inet {TABLE}\n"
       f"add chain inet {TABLE} output {{ type filter hook output priority mangle; policy accept; }}\n"
       f"add rule inet {TABLE} output oifname \"lo\" ip saddr {DE} ip daddr {DE} tcp sport 443 "
       "tcp flags & (syn | ack) == (syn | ack) counter tcp window set 4 "
       "\"MNEBY_IG_LOCAL_WINDOW4_ONLY\"\n")
# tcpdump -n -tt -i lo prints src IP.port > dest IP.port and flags/length.
PKT=re.compile(r"\bIP (\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*"
               r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):.*?"
               r"Flags \[([^\]]+)\].*?(?:win (\d+))?.*?\blength (\d+)")

def run(args, *, input=None, check=True, timeout=15):
    p=subprocess.run(args,input=input,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} returned {p.returncode}")
    return p

def exists():
    return run(["nft","list","table","inet",TABLE],check=False).returncode==0

def cleanup():
    if exists():
        run(["nft","delete","table","inet",TABLE])
    ok=not exists()
    print("localwin4_nft_cleaned="+str(ok).lower(),flush=True)
    if not ok:raise RuntimeError("test nft table persists")

def parse(lines,client_port):
    out=dict(synack_windows=[],client_lengths=[],server_lengths=[],synack=0)
    for line in lines.splitlines():
        m=PKT.search(line)
        if not m:continue
        src,sp,dst,dp,flags,win,length=m.groups()
        if src==DE and sp=="443" and dst==DE and dp==str(client_port):
            if "S" in flags and "." in flags:
                out["synack"]+=1
                if win is not None:out["synack_windows"].append(int(win))
            if int(length)>0:out["server_lengths"].append(int(length))
        if src==DE and sp==str(client_port) and dst==DE and dp=="443" and int(length)>0:
            out["client_lengths"].append(int(length))
    return out

def local_tls():
    ctx=ssl.create_default_context()
    sock=socket.create_connection((DE,443),timeout=4)
    port=sock.getsockname()[1]
    sock.settimeout(4)
    result="UNKNOWN"
    try:
        try:
            with ctx.wrap_socket(sock,server_hostname=HOST) as tls:
                result="VERIFIED_"+str(tls.version()) if tls.getpeercert() else "NO_CERT"
        except Exception as exc:
            result=type(exc).__name__
    finally:
        try:sock.close()
        except OSError:pass
    return port,result

def capture(phase):
    p=subprocess.Popen(["tcpdump","-i","lo","-n","-nn","-tt","-s","96","-l",
                        "tcp and host "+DE+" and port 443"],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(.4)
    if p.poll() is not None:
        raise RuntimeError("tcpdump did not initialize")
    try:
        port,result=local_tls()
        time.sleep(.4)
    finally:
        if p.poll() is None:p.send_signal(signal.SIGINT)
        try:output,errors=p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill();output,errors=p.communicate(timeout=2)
    result_info=parse(output,port)
    print("localwin4_"+phase+"_tls="+result,flush=True)
    print("localwin4_"+phase+"_synack="+str(result_info["synack"]),flush=True)
    print("localwin4_"+phase+"_synack_windows="+(",".join(map(str,result_info["synack_windows"])) or "NONE"),flush=True)
    print("localwin4_"+phase+"_client_segments="+str(len(result_info["client_lengths"])),flush=True)
    print("localwin4_"+phase+"_client_payload_lengths="+
          (",".join(map(str,result_info["client_lengths"][:24])) or "NONE"),flush=True)
    print("localwin4_"+phase+"_client_max_payload="+
          str(max(result_info["client_lengths"],default=0)),flush=True)
    print("localwin4_"+phase+"_headers_only=true",flush=True)
    return result_info

def selftest():
    # parser tests including SNI ClientHello split over 4-byte segments
    data="\n".join((
        f"IP {DE}.443 > {DE}.47005: Flags [S.], seq 1, ack 1, win 4, options [mss 65495], length 0",
        f"IP {DE}.47005 > {DE}.443: Flags [P.], seq 1:5, ack 1, win 512, length 4",
        f"IP {DE}.47005 > {DE}.443: Flags [P.], seq 5:9, ack 1, win 512, length 4",
        f"IP {DE}.47006 > {DE}.443: Flags [P.], seq 1:130, ack 1, win 512, length 129"))
    r=parse(data,47005)
    assert r["synack"]==1 and r["synack_windows"]==[4]
    assert r["client_lengths"]==[4,4]
    assert parse(data,47006)["client_lengths"]==[129]
    assert "oifname \"lo\"" in RULES and f"ip daddr {DE}" in RULES
    assert f"add table inet {TABLE}" in RULES
    print("localwin4_selftest=PASS")

def main():
    if sys.argv[1:]==["self-test"]:
        selftest();return
    if os.geteuid()!=0 or os.environ.get("MNEBY_LOCAL_W4_APPROVED")!="YES":
        raise RuntimeError("explicit owner-approved local-only root trial required")
    if not re.search(r"\s"+re.escape(DE)+r"/",run(["ip","-4","-o","addr","show"]).stdout):
        raise RuntimeError("unexpected host")
    for service in ("nginx.service","mnebydns-dot.service"):
        if run(["systemctl","is-active","--quiet",service],check=False).returncode:
            raise RuntimeError("baseline service inactive")
    if exists():raise RuntimeError("previous local test table still present")
    if not run(["systemctl","is-active","--quiet",UNIT+".timer"],check=False).returncode:
        raise RuntimeError("previous rollback watchdog still running")
    # Local route is essential; no clients on eth0 can match local-only nft rule.
    route=run(["ip","route","get",DE]).stdout
    if not re.search(r"\blocal\b|\bdev lo\b",route):
        raise RuntimeError("no DE-local route")
    run(["nft","--check","-f","-"],input=RULES)
    print("localwin4_nft_syntax=PASS",flush=True)
    a=capture("A")
    run(["systemd-run","--quiet","--collect","--unit",UNIT,"--on-active=80s",
         "/usr/sbin/nft","delete","table","inet",TABLE])
    if run(["systemctl","is-active","--quiet",UNIT+".timer"],check=False).returncode:
        raise RuntimeError("rollback timer did not arm")
    print("localwin4_independent_rollback_armed=true",flush=True)
    try:
        run(["nft","-f","-"],input=RULES)
        if not exists():raise RuntimeError("nft table not installed")
        print("localwin4_active_only_de_loopback=true",flush=True)
        b=capture("B")
        snap=run(["nft","list","table","inet",TABLE]).stdout
        counter=re.search(r"counter packets (\d+)",snap)
        print("localwin4_rule_synack_counter="+(counter.group(1) if counter else "UNKNOWN"),flush=True)
        cleanup()
        a2=capture("A2")
    finally:
        cleanup()
    for service in ("nginx.service","mnebydns-dot.service"):
        if run(["systemctl","is-active","--quiet",service],check=False).returncode:
            raise RuntimeError("service was interrupted")
    print("localwin4_post_services_active=true",flush=True)
    print("localwin4_android_tspu_path=NOT_TESTED",flush=True)
    print("localwin4_sni_split_confirmed="+
          ("true" if b["client_lengths"] and len(b["client_lengths"])>1
                    and max(b["client_lengths"])<=4 and 4 in b["synack_windows"]
           else "false"),flush=True)

if __name__=="__main__":
    main()
