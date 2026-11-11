#!/usr/bin/env python3
"""Read-only, peer-scoped TCP443 failure localization on DE.

During a concurrent client probe, compare SYN/SYN-ACK as seen on eth0
with the kernel's TCP state and source-filtered conntrack entries.
No nft changes, service restarts, DNS changes or raw IP/payload logs.
"""
from __future__ import annotations
import collections
import ipaddress
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

DE = "89.125.90.101"
CAPTURE_SECONDS = 18
RX = re.compile(r"\bIP (\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+): .*?\bFlags \[([^\]]+)\]")
STATES = ("SYN_SENT", "SYN_RECV", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT", "LAST_ACK", "UNREPLIED", "ASSURED")

def call(args, timeout=4):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def summarize(packet_text, peer):
    out=collections.Counter()
    for line in packet_text.splitlines():
        m=RX.search(line)
        if not m:
            continue
        src, sp, dst, dp, flags=m.groups()
        for port in ("443","853"):
            inbound=src==peer and dst==DE and dp==port
            outbound=src==DE and dst==peer and sp==port
            if not (inbound or outbound):
                continue
            direction="in" if inbound else "out"
            kind="SYNACK" if "S" in flags and "." in flags else "SYN" if "S" in flags else "RST" if "R" in flags else "ACK"
            out[f"{port}_{direction}_{kind}"]+=1
    return out

def queue_counter():
    file=pathlib.Path("/proc/net/netfilter/nfnetlink_queue")
    if not file.is_file():return None
    for line in file.read_text().splitlines():
        a=line.split()
        if len(a)>=8 and a[0]=="210":
            return dict(queued=int(a[2]), kernel_drop=int(a[5]), user_drop=int(a[6]), seq=int(a[7]))
    return None

def queue_worker_pid():
    p=call(["systemctl","show","telegram-foreign-nfqws.service","--property=MainPID"])
    m=re.search(r"MainPID=(\d+)",p.stdout)
    return int(m.group(1)) if m else None

def proc_ticks(pid):
    try:
        data=pathlib.Path(f"/proc/{pid}/stat").read_text()
        tail=data.rsplit(")",1)[1].strip().split()
        return int(tail[11])+int(tail[12])
    except (OSError,ValueError,IndexError):
        return None

def conntrack_flags(peer):
    if not shutil.which("conntrack"):return "tool_missing", ()
    # Source and destination matching is for original ingress only. Never log raw entries.
    r=call(["conntrack","-L","-f","ipv4","-p","tcp","--orig-src",peer,
            "--orig-dst",DE,"--dport","443"],timeout=4)
    if r.returncode not in (0,1):
        return "unavailable", ()
    text=r.stdout
    matches=tuple(name for name in STATES if re.search(r"\b"+name+r"\b",text))
    return ("found" if text.strip() else "empty"),matches

def local_tcp(host,port):
    try:
        with socket.create_connection((host,port),timeout=2):return "CONNECTED"
    except Exception as e:return type(e).__name__

def selftest():
    peer="198.51.100.7"
    data="\n".join([
        "01:00 eth0 In IP 198.51.100.7.45454 > 89.125.90.101.443: Flags [S], length 0",
        "01:00 eth0 Out IP 89.125.90.101.443 > 198.51.100.7.45454: Flags [S.], length 0",
        "01:00 eth0 In IP 198.51.100.7.45455 > 89.125.90.101.853: Flags [S], length 0",
        "01:00 eth0 Out IP 89.125.90.101.853 > 198.51.100.7.45455: Flags [S.], length 0",
        "01:00 eth0 In IP 198.51.100.8.45454 > 89.125.90.101.443: Flags [S], length 0"
    ])
    x=summarize(data,peer)
    assert x["443_in_SYN"]==1 and x["443_out_SYNACK"]==1
    assert x["853_in_SYN"]==1 and x["853_out_SYNACK"]==1
    assert sum(x.values())==4
    assert summarize("",peer)==collections.Counter()
    print("peerwise_offline_selftest=PASS")

def main():
    if sys.argv[1:]==["self-test"]:
        selftest();return
    if os.geteuid()!=0:raise RuntimeError("header-only capture requires root")
    ssh=os.environ.get("SSH_CONNECTION","").split()
    if len(ssh)!=4:raise RuntimeError("SSH peer missing")
    peer=str(ipaddress.IPv4Address(ssh[0]))
    if not ipaddress.ip_address(peer).is_global:raise RuntimeError("SSH peer must be public")
    own=call(["ip","-4","-o","addr","show"])
    if own.returncode or DE not in own.stdout:raise RuntimeError("host identity check failed")
    if not shutil.which("tcpdump"):raise RuntimeError("tcpdump missing")
    listener=call(["ss","-ltnH","sport","=",":443"])
    if listener.returncode or not listener.stdout.strip():raise RuntimeError("TCP443 listener absent")
    print("peerwise_local_loopback443="+local_tcp("127.0.0.1",443),flush=True)
    print("peerwise_local_public443="+local_tcp(DE,443),flush=True)
    print("peerwise_local_public853="+local_tcp(DE,853),flush=True)
    pid=queue_worker_pid()
    print("peerwise_queue_worker_pid_valid="+str(bool(pid)).lower(),flush=True)
    before_ticks=proc_ticks(pid) if pid else None
    before_q=queue_counter()
    p=subprocess.Popen(["tcpdump","-i","eth0","-nn","-l","-tt","-s","96","-c","300",
                        f"tcp and host {peer} and host {DE} and (port 443 or port 853)"],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(.4)
    if p.poll() is not None:raise RuntimeError("tcpdump failed")
    print("peerwise_observer=READY",flush=True)
    observed=collections.Counter()
    sample_count=0
    until=time.monotonic()+CAPTURE_SECONDS
    statuses=set()
    try:
        while time.monotonic()<until and p.poll() is None:
            ss=call(["ss","-H","-tn","state","syn-recv","sport","=",":443"],timeout=2)
            if ss.returncode==0:
                n=sum(peer in ln for ln in ss.stdout.splitlines())
                observed["peer_synrecv_peak"]=max(observed["peer_synrecv_peak"],n)
            mode,flags=conntrack_flags(peer)
            observed["conntrack_"+mode]+=1
            statuses.update(flags)
            sample_count+=1
            time.sleep(.35)
    finally:
        if p.poll() is None:p.send_signal(signal.SIGINT)
        try: stdout,stderr=p.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill();stdout,stderr=p.communicate(timeout=3)
    for k in ("443_in_SYN","443_out_SYNACK","443_in_ACK","443_out_ACK","443_in_RST","443_out_RST",
              "853_in_SYN","853_out_SYNACK","853_in_ACK","853_out_ACK"):
        print("peerwise_"+k+"="+str(summarize(stdout,peer)[k]),flush=True)
    print("peerwise_synrecv_peak="+str(observed["peer_synrecv_peak"]),flush=True)
    print("peerwise_conntrack_samples="+str(sample_count),flush=True)
    print("peerwise_conntrack_found="+str(observed["conntrack_found"]),flush=True)
    print("peerwise_conntrack_empty="+str(observed["conntrack_empty"]),flush=True)
    print("peerwise_conntrack_unavailable="+str(observed["conntrack_unavailable"]),flush=True)
    print("peerwise_conntrack_states="+(",".join(sorted(statuses)) or "NONE"),flush=True)
    after_q=queue_counter()
    if before_q and after_q:
        for key in ("queued","kernel_drop","user_drop","seq"):
            print("peerwise_global_queue_"+key+"_delta="+str(after_q[key]-before_q[key]),flush=True)
    after_ticks=proc_ticks(pid) if pid else None
    if before_ticks is not None and after_ticks is not None:
        print("peerwise_worker_cpu_ticks_delta="+str(after_ticks-before_ticks),flush=True)
    print("peerwise_source_is_ssh_ip_probes_may_have_different_nat=UNCHECKED",flush=True)
    print("peerwise_raw_addresses_or_payload_logged=false",flush=True)
    print("peerwise_server_changes=NONE",flush=True)

if __name__=="__main__":
    main()
