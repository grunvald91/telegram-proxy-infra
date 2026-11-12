#!/usr/bin/env python3
"""Public TLS receiver test from GitHub runner; NO DNS/nginx modifications.

Only a single GitHub runner IP is DNATed to a separately launched server
listener; independent same-boot cleanup timer is armed *before* nft changes.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from meta_v15_receive_window import nft_rules,verify_queue_exemption

STAGE=Path("/usr/local/libexec/mneby-meta-v20")
STATE=Path("/var/lib/mneby-meta-v20-probe")
WORKER="mneby-meta-v20-worker"
CLEANUP="mneby-meta-v20-cleanup"
TABLE="mneby_meta_v20_public"
EDGE="89.125.90.101"
PORT=18443

def cmd(args,*,input=None,timeout=15,check=True):
    result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(args[0]+" returned "+str(result.returncode))
    return result

def table_exists():
    obj=json.loads(cmd(["nft","-j","list","tables"]).stdout)
    return any(x.get("table",{}).get("family")=="inet" and
               x.get("table",{}).get("name")==TABLE
               for x in obj["nftables"])

def cleanup():
    errors=[]
    try:
        if table_exists():cmd(["nft","delete","table","inet",TABLE])
    except Exception:errors.append("table_cleanup")
    try:cmd(["systemctl","stop",WORKER+".service"],timeout=15,check=False)
    except Exception:errors.append("worker_cleanup")
    try:
        if table_exists():errors.append("table_still_present")
    except Exception:errors.append("table_check")
    if errors:
        raise RuntimeError("cleanup_failed_"+",".join(errors))
    if STATE.exists():shutil.rmtree(STATE)
    print("meta_v20_public_cleanup=VERIFIED",flush=True)

def start(peer):
    peer=str(ipaddress.IPv4Address(peer))
    if not ipaddress.IPv4Address(peer).is_global or peer==EDGE:
        raise ValueError("runner public IPv4 required")
    if os.geteuid()!=0 or Path(__file__).resolve().parent!=STAGE:
        raise RuntimeError("root and persistent owned stage required")
    if STATE.exists() or table_exists():
        raise RuntimeError("prior public probe state already exists")
    for name in (WORKER+".service",CLEANUP+".timer"):
        if cmd(["systemctl","is-active","--quiet",name],check=False).returncode==0:
            raise RuntimeError("prior probe unit active")
    for name in ("nginx.service","mnebydns-dot.service"):
        if cmd(["systemctl","is-active","--quiet",name],check=False).returncode:
            raise RuntimeError("production service not ready")
    if cmd(["ss","-H","-lnt","sport","=",":"+str(PORT)]).stdout.strip():
        raise RuntimeError("dedicated test port occupied")
    net=json.loads(cmd(["nft","-j","list","ruleset"]).stdout)
    verify_queue_exemption(net)
    rules=nft_rules(EDGE,peer,port=PORT,table=TABLE)
    cmd(["nft","--check","-f","-"],input=rules)
    STATE.mkdir(mode=0o700)
    try:
        # A separate timer owns complete cleanup even when GitHub runner exits.
        cmd(["systemd-run","--quiet","--collect","--unit",CLEANUP,
             "--on-active=180s","/usr/bin/python3",
             str(STAGE/"meta_v20_public_probe.py"),"cleanup"])
        if cmd(["systemctl","is-active","--quiet",CLEANUP+".timer"],check=False).returncode:
            raise RuntimeError("independent cleanup not armed")
        cmd(["systemd-run","--quiet","--collect","--unit",WORKER,
             "--property=RuntimeMaxSec=180","--property=KillMode=control-group",
             "/usr/bin/python3","-u",str(STAGE/"meta_v15_receive_window.py"),
             "--peer",peer,"--edge",EDGE,"--port",str(PORT),
             "--max-lifetime","1500"])
        for _ in range(60):
            status=cmd(["systemctl","is-active","--quiet",WORKER+".service"],check=False)
            ss=cmd(["ss","-H","-lnt","sport","=",":"+str(PORT)],check=False)
            if status.returncode==0 and EDGE+":"+str(PORT) in ss.stdout:break
            time.sleep(.1)
        else:raise RuntimeError("worker not listening")
        cmd(["nft","-f","-"],input=rules)
        print("meta_v20_public_probe_ready=true",flush=True)
    except BaseException:
        cleanup()
        raise

def inspect():
    print("meta_v20_public_probe_table_present="+str(table_exists()).lower(),flush=True)
    if not table_exists():return
    r=json.loads(cmd(["nft","-j","list","table","inet",TABLE]).stdout)
    for entry in r.get("nftables",[]):
        rule=entry.get("rule",{})
        if rule.get("chain") in ("pre","out"):
            n=sum(e["counter"].get("packets",0) for e in rule.get("expr",[]) if "counter" in e)
            print("meta_v20_public_"+rule["chain"]+"_packets="+str(n),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("start","inspect","cleanup"))
    p.add_argument("--peer")
    args=p.parse_args()
    if args.mode=="start":
        if not args.peer:p.error("start requires --peer")
        start(args.peer)
    elif args.mode=="inspect":inspect()
    else:cleanup()
