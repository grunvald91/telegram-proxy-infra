#!/usr/bin/env python3
"""Read-only aggregate peer-only TCP failure diagnostics; never log IP or payload."""
import collections
import json
from pathlib import Path
import re
import subprocess
import time

CONTROLLER=Path("/var/lib/mneby-meta-v15-controller")

def run(argv, timeout=15):
    return subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          text=True,timeout=timeout,check=False)

def show(k,v):
    print("meta_v16_tcp_"+k+"="+str(v),flush=True)

if not CONTROLLER.joinpath("peer").exists():
    show("state","NO_ACTIVE_PEER")
    raise SystemExit(0)
peer=CONTROLLER.joinpath("peer").read_text().strip()
if not re.fullmatch(r"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",peer):
    raise SystemExit("invalid peer state")

# ss state enumeration is local only, no output addresses.
for params in (["ss","-H","-n","-t","-a","sport","=",":18443"],
               ["ss","-H","-n","-t","-a","sport","=",":443"]):
    r=run(params,timeout=4)
    c=collections.Counter(line.split()[0] for line in r.stdout.splitlines() if line.split())
    label="proxy" if "18443" in params else "nginx"
    for state,count in sorted(c.items()):
        show("ss_"+label+"_"+state.lower().replace("-","_"),count)

# Inspect nft chain rules counters (aggregate, not addresses).
r=run(["nft","-j","list","table","inet","mneby_meta_v15"])
if r.returncode==0:
    rules=json.loads(r.stdout).get("nftables",[])
    for ent in rules:
        if ent.get("rule",{}).get("chain") in ("pre","out"):
            rule=ent["rule"]
            counters=[x["counter"] for x in rule.get("expr",[]) if "counter" in x]
            show("nft_"+rule["chain"]+"_packets",
                 sum(c.get("packets",0) for c in counters))

# tcpdump short, metadata-only, with package headers captured; bounded 10s.
cmd=["timeout","12s","tcpdump","-i","eth0","-q","-nn","-l",
     "-s","96","tcp and host "+peer+" and host 89.125.90.101 and port 443"]
try:
    proc=run(cmd,timeout=15)
    lines=proc.stdout.splitlines()
    counts=collections.Counter()
    for line in lines:
        if "Flags [S.]" in line:counts["synack"]+=1
        elif "Flags [S]" in line:counts["syn"]+=1
        elif "Flags [R" in line:counts["rst"]+=1
        else:counts["other"]+=1
        m=re.search(r"length (\\d+)",line)
        if m and int(m.group(1))>0:
            counts["payload_packets"]+=1
            if int(m.group(1))<=8:counts["payload_up_to_8"]+=1
            else:counts["payload_gt_8"]+=1
    show("tcpdump_sample_seconds",12)
    show("tcpdump_total_packets",sum(v for k,v in counts.items() if k in ("syn","synack","rst","other")))
    for key in ("syn","synack","rst","other","payload_packets","payload_up_to_8","payload_gt_8"):
        show("tcpdump_"+key,counts[key])
except Exception as e:
    show("tcpdump_error",type(e).__name__)
show("read_only",True)
