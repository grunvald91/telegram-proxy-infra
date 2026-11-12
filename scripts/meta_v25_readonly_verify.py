#!/usr/bin/env python3
"""DE production CoreDNS view compatibility preflight. NO writes/service changes."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from meta_v25_source_view import render

CORE=Path("/opt/mnebydns-dot/Corefile")

def check():
    service=subprocess.run(["systemctl","is-active","--quiet","mnebydns-dot.service"],
                           timeout=6,check=False)
    if service.returncode:
        raise RuntimeError("current DoT service inactive")
    show=subprocess.run(["systemctl","show","-P","MainPID","mnebydns-dot.service"],
                        capture_output=True,text=True,timeout=6,check=True)
    pid=int(show.stdout.strip())
    if pid<=0:raise RuntimeError("DoT service has no running binary")
    plugins=subprocess.run(["/proc/"+str(pid)+"/exe","-plugins"],
                           capture_output=True,text=True,timeout=8,check=True)
    source=CORE.read_text()
    # Synthetic peer only: no owner IP stored in Git or production config.
    plan=render(corefile=source,phone_ip="8.8.8.8",
                compiled_plugins=plugins.stdout)
    plan.verify_rollback()
    assert plan.candidate.endswith(source)
    print("meta_v25_live_corefile_view_compatible=true",flush=True)
    print("meta_v25_compiled_view_plugin=true",flush=True)
    print("meta_v25_exact_source_view_count=1",flush=True)
    print("meta_v25_exact_meta_hosts="+str(plan.selected_hosts),flush=True)
    print("meta_v25_default_corefile_byte_preserved=true",flush=True)
    print("meta_v25_read_only_no_writes=true",flush=True)

if __name__=="__main__":
    try:check()
    except Exception as exc:
        print("meta_v25_live_corefile_view_compatible=false",flush=True)
        print("meta_v25_block_reason="+type(exc).__name__,flush=True)
        raise SystemExit(1)
