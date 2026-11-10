#!/usr/bin/env python3
"""RU read-only netfilter counter delta while one trusted runner probes 80/443.

Counters aggregate unrelated traffic; differences suggest rule hits, not
cryptographic attribution to the test connection. No payload captured.
"""
from __future__ import annotations

import re
import subprocess
import sys
import time

CHAINS = {
    "filter": ("INPUT", "ufw-before-input", "ufw-user-input", "ufw-after-input", "ufw-reject-input"),
    "mangle": ("PREROUTING", "INPUT"),
    "raw": ("PREROUTING",),
    "security": ("INPUT",),
}

def cmd(args):
    try:
        return subprocess.run(args,text=True,capture_output=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None

def snapshot():
    result = {}
    for table, chains in CHAINS.items():
        for chain in chains:
            p=cmd(["iptables","-w","-t",table,"-n","-v","-x","-L",chain])
            q=cmd(["iptables","-w","-t",table,"-S",chain])
            if not p or p.returncode or not q or q.returncode:
                continue
            rows=[]
            for line in p.stdout.splitlines():
                parts=line.split()
                if len(parts)>=3 and parts[0].isdigit() and parts[1].isdigit():
                    rows.append((int(parts[0]),parts[2]))
            rule_lines=[x for x in q.stdout.splitlines() if x.startswith("-A ")]
            if len(rows)!=len(rule_lines):
                print(f"counter_mapping_{table}_{chain}=NOT_ALIGNED",flush=True)
                continue
            for i,((pkts,target),definition) in enumerate(zip(rows,rule_lines),1):
                result[(table,chain,i)]=(pkts,target,definition)
    return result

def main():
    if len(sys.argv)!=1:
        raise SystemExit("No parameters accepted")
    before=snapshot()
    print("ru_rule_counter_capture=READY",flush=True)
    time.sleep(17)
    after=snapshot()
    total=0
    for key,(packets_after,target,definition) in after.items():
        if key not in before:continue
        packets_before=before[key][0]
        delta=packets_after-packets_before
        if delta <=0:continue
        table,chain,position=key
        # Structural description excludes literal IPs and potentially sensitive
        # network configuration details, while keeping the rule classification.
        port80="--dport 80" in definition
        port443=bool(re.search(r"--dport 443(?:\s|$)",definition))
        port18443=bool(re.search(r"--dport 18443(?:\s|$)",definition))
        source_scoped=bool(re.search(r"(?:-s|--source)\s",definition))
        drop_like=target in ("DROP","REJECT","SYNPROXY")
        if table=="filter" or drop_like or port443 or port18443:
            print(f"rule_hit_{table}_{chain}_{position}=delta:{delta},target:{target},"
                  f"port80:{str(port80).lower()},port443:{str(port443).lower()},"
                  f"port18443:{str(port18443).lower()},source_scoped:{str(source_scoped).lower()}",
                  flush=True)
            total+=1
    print(f"counter_rules_with_activity={total}",flush=True)
    p=cmd(["ss","-H","-lnt","sport", "=",":443"])
    print("local_tcp443_listener_present="+str(bool(p and p.returncode==0 and p.stdout.strip())).lower())
    for iface in ("all","default"):
        p=cmd(["sysctl","-n",f"net.ipv4.conf.{iface}.rp_filter"])
        if p and p.returncode==0:
            print(f"rp_filter_{iface}={p.stdout.strip()}")
    print("ru_rule_counter_capture=COMPLETE_READ_ONLY",flush=True)

if __name__=="__main__":
    main()
