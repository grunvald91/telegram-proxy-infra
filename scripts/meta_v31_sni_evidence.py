#!/usr/bin/env python3
"""RU ingress SNI packet evidence, PCAP kept in memory only.

The result proves observed TCP segmentation, never Android login/feed or a
TSPU bypass. Kernel drops, parser errors, early EOF and ambiguous boundaries
cannot produce a successful final result. Reports contain no client IP/payload.
"""
from __future__ import annotations
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

from mnebydns_iglite_sni_observer import Analyzer,capture_command,parse_pcap
from meta_v15_receive_window import HOSTS

POINT="RU_ENS3_INBOUND_PRE_DNAT"
COUNTERS=("syn","target_clienthello","sni_split","sni_unsplit",
          "sni_boundary_indeterminate","evictions","payload_without_syn")

def final_verdict(report):
    if report.get("final") is not True:
        return "CAPTURING"
    if not report.get("capture_ok") or report.get("kernel_drops")!=0:
        return "CAPTURE_INVALID"
    stats=report["stats"]
    if stats["sni_unsplit"]:
        return "UNSPLIT_SNI_OBSERVED"
    if stats["sni_boundary_indeterminate"] or stats["evictions"]:
        return "SEGMENTATION_INDETERMINATE"
    if not stats["target_clienthello"]:
        return "NO_TARGET_CLIENTHELLO"
    if stats["sni_split"]!=stats["target_clienthello"]:
        return "SEGMENTATION_INDETERMINATE"
    return "SNI_SEGMENTATION_OBSERVED"

def validate_report(report,*,final=False,now=None):
    if (report.get("schema")!=1 or report.get("capture_point")!=POINT
            or type(report.get("worker_pid")) is not int or report["worker_pid"]<=0):
        raise RuntimeError("unrecognized RU packet evidence")
    now=time.time() if now is None else now
    updated=report.get("updated_at",0)
    if (type(updated) not in (int,float) or not math.isfinite(updated)
            or updated<=0 or (not final and not 0<=now-updated<=15)):
        raise RuntimeError("RU packet observer heartbeat stale")
    if not report.get("capture_ok"):
        raise RuntimeError("RU packet capture failed")
    stats=report.get("stats",{})
    if any(type(stats.get(k)) is not int or stats[k]<0 for k in COUNTERS):
        raise RuntimeError("RU packet evidence counters invalid")
    if final and final_verdict(report)!="SNI_SEGMENTATION_OBSERVED":
        raise RuntimeError("RU SNI measurement: "+final_verdict(report))

def write_report(path,report):
    # Single owned writer; readers only see whole JSON documents.
    tmp=path.with_name(path.name+".tmp")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as out:
        json.dump(report,out,sort_keys=True)
        out.flush();os.fsync(out.fileno())
    os.replace(tmp,path)

class CaptureEvidence:
    def __init__(self,peer,path):
        self.path=Path(path)
        self.command=capture_command(edge="188.120.254.223",peer=None if peer=="all" else peer)
        self.analyzer=Analyzer(HOSTS)
        self.ready=threading.Event()
        self.stopping=threading.Event()
        self.failures=[]
        self.process=None
        self.thread=None
        self.drops=None
        self.finished=False

    def start(self):
        self.process=subprocess.Popen(self.command,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,bufsize=0,env=dict(os.environ,LC_ALL="C"))
        def consume():
            try:
                parse_pcap(self.process.stdout,self.analyzer,self.ready)
                if not self.stopping.is_set():self.failures.append("UnexpectedCaptureEOF")
            except Exception as exc:
                self.failures.append(type(exc).__name__)
                self.ready.set()
        self.thread=threading.Thread(target=consume,daemon=True)
        self.thread.start()
        if not self.ready.wait(4) or not self.healthy():
            self.stop()
            raise RuntimeError("RU ingress packet capture did not become ready")
        self.publish()

    def healthy(self):
        return (not self.failures and self.process is not None
                and self.process.poll() is None and self.thread.is_alive())

    def report(self,proxy_stats=None):
        a=self.analyzer
        hosts={host:{"hello":a.host_counts[host],"split":0,"unsplit":0} for host in sorted(HOSTS)}
        # Events are bounded in the observer. Global counters stay authoritative
        # after that bound; per-host event counts are explicitly partial.
        events=list(a.events)
        for _sec,_source,host,split in events:
            hosts[host]["split" if split else "unsplit"]+=1
        result={"schema":1,"capture_point":POINT,"worker_pid":os.getpid(),
                "updated_at":time.time(),"final":self.finished,
                "capture_ok":not self.failures and (self.finished or self.healthy()),
                "kernel_drops":self.drops,"stats":{key:a.stats[key] for key in COUNTERS},
                "hosts":hosts,"per_host_events_limited":len(events)>=512,
                "incomplete":dict(a.incomplete_diagnostics()) if self.finished else {},
                "failure_codes":list(self.failures),"pcap_written":False,
                "uncovered_meta_hosts":sorted(host for host in list(a.uncovered_meta)
                    if re.fullmatch(r"[a-z0-9.-]{1,253}",host)),
                "android_login_feed":"NOT_VERIFIED"}
        result["verdict"]=final_verdict(result)
        if proxy_stats is not None:result["proxy"]=dict(proxy_stats)
        return result

    def publish(self,proxy_stats=None):
        report=self.report(proxy_stats)
        write_report(self.path,report)
        return report

    def stop(self):
        if self.finished:return
        self.stopping.set()
        if self.process is not None:
            if self.process.poll() is None:self.process.send_signal(signal.SIGINT)
            self.thread.join(timeout=6)
            if self.thread.is_alive():
                self.process.kill();self.thread.join(timeout=3)
                self.failures.append("CaptureStopTimeout")
            try:status=self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill();status=self.process.wait(timeout=3)
                self.failures.append("CaptureExitTimeout")
            if status!=0:self.failures.append("CaptureExit"+str(status))
            diagnostics=self.process.stderr.read().decode("ascii",errors="replace")
            matches=re.findall(r"(?m)^(\d+) packets dropped by kernel$",diagnostics)
            if len(matches)!=1:self.failures.append("MissingCaptureDropStatistics")
            else:self.drops=int(matches[0])
            if self.thread.is_alive():self.failures.append("CaptureReaderStillRunning")
            self.process.stdout.close();self.process.stderr.close()
        else:self.failures.append("CaptureNotStarted")
        self.finished=True
