#!/usr/bin/env python3
"""Bounded FI clock recovery; keep native NTP enabled.

Based on the existing relay89 HTTPS clock guard, with two independent
verified HTTPS Date sources, forward-only correction and FI host fence.
Never changes RU/DE, firewall, DNS/VPN services or signed TTL.
"""
from __future__ import annotations
import email.utils
import fcntl
import json
import os
import socket
import statistics
import struct
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

FI="217.11.167.91"
SOURCES=("https://www.google.com/generate_204",
         "https://www.cloudflare.com/cdn-cgi/trace",
         "https://api.telegram.org/")
MAX_STEP=120
TOLERANCE=4

def guard_host():
    if os.geteuid()!=0:raise ValueError("root_required")
    for _,name in socket.if_nameindex():
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                value=fcntl.ioctl(sock.fileno(),0x8915,struct.pack("256s",name.encode()))
                if socket.inet_ntoa(value[20:24])==FI:return
        except OSError:pass
    raise ValueError("unexpected_host")

def checked_offset(samples):
    values=[offset for offset,rtt in samples if 0<=rtt<=3]
    if len(values)<2 or max(values)-min(values)>2:
        raise ValueError("insufficient_agreeing_time_sources")
    offset=statistics.median(values)
    if not -TOLERANCE<=offset<=MAX_STEP:
        raise ValueError("clock_offset_outside_forward_repair_bound")
    return offset

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None

def sample_sources():
    # Explicitly bypass any environment proxy. HTTP redirects are not
    # accepted as independent time authorities. Standard CA validation.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    samples=[]
    for idx,source in enumerate(SOURCES):
        start=time.time()
        mono=time.monotonic()
        try:
            request=urllib.request.Request(source+"?clockcheck="+uuid.uuid4().hex,
                headers={"Cache-Control":"no-cache, no-store","Pragma":"no-cache",
                         "User-Agent":"mnebyvpn-fi-clock/1"})
            with opener.open(request,timeout=4) as response:
                age=response.headers.get("Age","0")
                if age!="0":raise ValueError("cached_date")
                date=email.utils.parsedate_to_datetime(response.headers["Date"])
                if date.tzinfo is None:raise ValueError("ambiguous_date")
                remote=date.timestamp()
            rtt=time.monotonic()-mono
            if abs((time.time()-start)-rtt)>.5:raise ValueError("clock_changed_during_sample")
            delta=remote-(start+rtt/2)
            samples.append((delta,rtt))
            print("FI_CLOCK_HTTPS_SAMPLE="+json.dumps({"source":idx,"offset_ms":round(delta*1000),"rtt_ms":round(rtt*1000)}),flush=True)
        except (OSError,ValueError,TypeError,OverflowError) as exc:
            print("FI_CLOCK_HTTPS_SAMPLE_FAILED="+str(idx)+":"+type(exc).__name__,flush=True)
    return checked_offset(samples)

def ntp_synchronized():
    result=subprocess.run(["/usr/bin/timedatectl","show","-p","NTPSynchronized","--value"],
                           capture_output=True,text=True,timeout=5)
    return result.returncode==0 and result.stdout.strip()=="yes"

def main():
    guard_host()
    if sys.argv[1:] not in (["--repair"],["--fallback"]):raise ValueError("invalid_mode")
    if sys.argv[1:] == ["--fallback"] and ntp_synchronized():
        print("FI_CLOCK_NATIVE_NTP_SYNC=true",flush=True)
        return
    offset=sample_sources()
    if offset>TOLERANCE:
        time.clock_settime(time.CLOCK_REALTIME,time.time()+offset)
        print("FI_CLOCK_FORWARD_STEP_MS="+str(round(offset*1000)),flush=True)
        verified=sample_sources()
        if abs(verified)>TOLERANCE:raise ValueError("clock_repair_verification_failed")
    else:verified=offset
    print("FI_CLOCK_REPAIR_VERIFIED=true;HTTPS_OFFSET_MS="+str(round(verified*1000)),flush=True)
    print("FI_CLOCK_NATIVE_NTP_SYNC="+str(ntp_synchronized()).lower(),flush=True)

if __name__=="__main__":
    try:main()
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        # Do not emit URL/error bodies or environment.
        print("FI_CLOCK_REPAIR_BLOCKED="+(str(exc) if isinstance(exc,ValueError) and str(exc).replace("_","").isalnum() else type(exc).__name__),file=sys.stderr)
        raise SystemExit(2)
