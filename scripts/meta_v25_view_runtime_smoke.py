#!/usr/bin/env python3
"""Real CoreDNS view source-IP smoke on localhost port 15533.

Launches a temporary CoreDNS child bound to loopback for two synthetic clients,
tests DNS A answers, then terminates it. NEVER changes production Corefile,
production port 853, nft, or systemd units.
"""
from __future__ import annotations
from pathlib import Path
import ipaddress
import os
import socket
import struct
import subprocess
import tempfile
import time

PORT=15533
HOST="pilot.example.com"
VIEW_A="188.120.254.223"
BASELINE_A="89.125.90.101"

def dns_question():
    domain=b"".join(bytes((len(label),))+label.encode("ascii") for label in HOST.split("."))+b"\x00"
    return struct.pack("!HHHHHH",0x2585,0x0100,1,0,0,0)+domain+struct.pack("!HH",1,1)

def dns_a_from(peer):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        s.bind((peer,0))
        s.sendto(dns_question(),("127.0.0.1",PORT))
        data,_=s.recvfrom(512)
    if len(data)<28 or data[:2]!=b"\x25\x85":
        raise AssertionError("synthetic DNS request not answered")
    if struct.unpack_from("!H",data,6)[0]!=1:
        raise AssertionError("synthetic response does not contain one answer")
    return str(ipaddress.IPv4Address(data[-4:]))

def run():
    svc=subprocess.run(["systemctl","show","-P","MainPID","mnebydns-dot.service"],
                       capture_output=True,text=True,timeout=5,check=True)
    pid=int(svc.stdout.strip())
    if pid<=0:raise RuntimeError("production CoreDNS binary not active")
    exe="/proc/"+str(pid)+"/exe"
    core=(""".:15533 {
    bind 127.0.0.1
    view pilot {
        expr client_ip() == '127.0.0.1'
    }
    template IN A . {
        match ^pilot[.]example[.]com[.]$
        answer "{{ .Name }} 5 IN A 188.120.254.223"
    }
}
.:15533 {
    bind 127.0.0.1
    template IN A . {
        match ^pilot[.]example[.]com[.]$
        answer "{{ .Name }} 5 IN A 89.125.90.101"
    }
}
""")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1",PORT))
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1",PORT))
    with tempfile.TemporaryDirectory(prefix="mneby-v25-core-smoke-") as d:
        config=Path(d)/"Corefile"
        config.write_text(core)
        config.chmod(0o600)
        process=subprocess.Popen([exe,"-conf",str(config)],cwd=d,
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+6
            while time.monotonic()<deadline:
                if process.poll() is not None:
                    raise RuntimeError("CoreDNS child failed to start view server")
                try:
                    first=dns_a_from("127.0.0.1")
                    other=dns_a_from("127.0.0.2")
                    break
                except (TimeoutError,ConnectionError,AssertionError,OSError):
                    time.sleep(.15)
            else:raise RuntimeError("CoreDNS child did not respond")
            if first!=VIEW_A or other!=BASELINE_A:
                raise AssertionError("source-IP DNS split returned incorrect addresses")
            print("meta_v25_core_view_real_runtime=PASS",flush=True)
            print("meta_v25_source_127001_to_RU188=PASS",flush=True)
            print("meta_v25_source_127002_to_unmodified_DE89=PASS",flush=True)
            print("meta_v25_only_loopback_15533_used=true",flush=True)
        finally:
            process.terminate()
            try:process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    print("meta_v25_smoke_child_stopped=true",flush=True)
    print("meta_v25_production_configs_untouched=true",flush=True)

if __name__=="__main__":run()
