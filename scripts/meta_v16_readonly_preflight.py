#!/usr/bin/env python3
"""30-minute Meta peer trial preflight: READ ONLY, no production changes.

Execute as root on the DE node with the three peer trial modules adjacent.
The script intentionally never prints IPs, secrets, full nft config or SNI.
"""
from __future__ import annotations
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

EDGE = "89.125.90.101"
NGINX = Path("/etc/nginx/nginx.conf")
CORE = Path("/opt/mnebydns-dot/Corefile")
STATE = Path("/var/lib/mneby-meta-v15-controller")
ROUTES = Path("/var/lib/mneby-meta-v15-routes")

def run(args, timeout=9):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def status(check, result):
    print("meta_v16_preflight_" + check + "=" + ("PASS" if result else "FAIL"), flush=True)
    return bool(result)

def run_preflight():
    import meta_v15_phone_trial as trial
    from meta_v15_receive_window import verify_queue_exemption
    conditions = []
    def require(name, ok):
        conditions.append(status(name,ok))
    try:
        cfg = run(["nginx","-t"])
        require("nginx_syntax",cfg.returncode == 0)
    except (OSError,subprocess.TimeoutExpired):
        require("nginx_syntax",False)
    try:
        addresses=run(["ip","-4","-o","addr","show"]).stdout
        require("de_edge_attached",bool(re.search(r"\s"+re.escape(EDGE)+r"/",addresses)))
    except (OSError,subprocess.TimeoutExpired):
        require("de_edge_attached",False)
    require("live_owned_configs_present", NGINX.is_file() and CORE.is_file())
    for svc in ("nginx.service","mnebydns-dot.service"):
        try:
            ok=run(["systemctl","is-active","--quiet",svc]).returncode == 0
        except (OSError,subprocess.TimeoutExpired):
            ok=False
        require(svc.replace(".service","").replace("-","_")+"_active",ok)
    try:
        window=Path("/proc/sys/net/ipv4/tcp_window_scaling").read_text().strip()
        require("tcp_window_scaling_normal",window == "1")
    except OSError:
        require("tcp_window_scaling_normal",False)
    require("v15_state_absent",not STATE.exists() and not ROUTES.exists())
    try:
        listeners=run(["ss","-H","-lnt","sport","=",":18443"]).stdout
        require("dedicated_tcp_port_free",not listeners.strip())
    except (OSError,subprocess.TimeoutExpired):
        require("dedicated_tcp_port_free",False)
    for unit in ("mneby-meta-v15-cleanup.timer",
                 "mneby-meta-v15-proxy.service",
                 "mneby-meta-v15-route-watchdog.timer",
                 "mneby-ig-lite-wifi-20261111-v10.timer"):
        try:
            active=run(["systemctl","is-active","--quiet",unit]).returncode == 0
        except (OSError,subprocess.TimeoutExpired):
            active=True
        require("no_"+unit.replace("-","_").replace(".","_").replace("@","_"),not active)
    try:
        tables=json.loads(run(["nft","-j","list","tables"]).stdout)
        present=any(item.get("table",{}).get("family")=="inet" and
                    item.get("table",{}).get("name")==trial.TABLE
                    for item in tables["nftables"])
        require("no_v15_nft_table",not present)
    except (ValueError,KeyError,OSError,subprocess.TimeoutExpired):
        require("no_v15_nft_table",False)
    try:
        ruleset=json.loads(run(["nft","-j","list","ruleset"]).stdout)
        valid=bool(verify_queue_exemption(ruleset))
        require("queue210_exemption_exact",valid)
    except (ValueError,KeyError,OSError,subprocess.TimeoutExpired):
        require("queue210_exemption_exact",False)
    try:
        watchdog,final=trial.time_budget(1800)
        require("30min_watchdog_budget",watchdog==2400 and final==2700)
    except Exception:
        require("30min_watchdog_budget",False)
    ready=all(conditions)
    print("meta_v16_preflight_ready="+str(ready).lower(),flush=True)
    return 0 if ready else 1

if __name__=="__main__":
    if len(sys.argv)!=1:raise SystemExit("no CLI options")
    raise SystemExit(run_preflight())
