#!/usr/bin/env python3
"""Read-only coarse firewall/listener audit for RU Instagram test ingress.

No full config, private addresses, client connections or packet payload printed.
"""
import pathlib
import re
import shutil
import subprocess

def run(args):
    if not shutil.which(args[0]):
        return None
    try:
        return subprocess.run(args,text=True,capture_output=True,timeout=12,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None

def owner_summary():
    p=run(["ss","-H","-lntp"])
    if p is None or p.returncode:
        print("listener_owner_inventory=UNAVAILABLE")
        return
    for port in (22,80,443,853,18443):
        selected=[l for l in p.stdout.splitlines() if re.search(rf":{port}\s",l)]
        owners=set()
        binds=set()
        for l in selected:
            owners.update(re.findall(r'users:\(\("([^"]+)"',l))
            fields=l.split()
            if len(fields)>3:
                b=fields[3]
                binds.add("wildcard" if b.startswith(("0.0.0.0:","*:","[::]:")) else
                         "public-v4" if b.startswith("188.120.254.223:") else
                         "loopback" if b.startswith(("127.","[::1]:")) else "other")
        print(f"tcp_port_{port}_owners={','.join(sorted(owners)) or 'none'}")
        print(f"tcp_port_{port}_bind_types={','.join(sorted(binds)) or 'none'}")

def firewall_summary():
    for chain in ("INPUT","ufw-before-input","ufw-user-input","ufw-after-input","OUTPUT"):
        p=run(["iptables","-w","-S",chain])
        if p is None or p.returncode:
            print(f"firewall_{chain}_inspect=UNAVAILABLE")
            continue
        print(f"firewall_{chain}_inspect=OK")
        for i,line in enumerate(p.stdout.splitlines()[:45]):
            if line.startswith("-P "):
                print(f"firewall_{chain}_policy={line.split()[-1]}")
                continue
            action=re.search(r"-j\s+([A-Za-z0-9_-]+)",line)
            verdict=action.group(1) if action else "other"
            has_443=bool(re.search(r"(?:--dport\s+443\b|--dports\s+[^\n]*\b443\b)",line))
            has_test=bool(re.search(r"(?:--dport\s+18443\b|--dports\s+[^\n]*\b18443\b)",line))
            if chain=="INPUT" or has_443 or has_test or verdict in ("DROP","REJECT"):
                print(f"firewall_{chain}_rule_{i}=target:{verdict},port443:{str(has_443).lower()},port18443:{str(has_test).lower()},source_scoped:{str(bool(re.search(r'-s\s+',line))).lower()}")
    p=run(["ufw","status","verbose"])
    if p and p.returncode==0:
        status=next((x.strip() for x in p.stdout.splitlines() if x.startswith("Status:")),"unknown")
        print("ufw_"+status.lower().replace(" ","_").replace(":","="))
        for item in p.stdout.splitlines():
            if re.search(r"\b(18443|443)\b",item) and re.search(r"ALLOW|DENY|REJECT",item):
                print("ufw_port_rule="+
                      ("18443" if re.search(r"\b18443\b",item) else "443")+
                      ",action="+("ALLOW" if "ALLOW" in item else "DENY" if "DENY" in item else "REJECT"))
    p=run(["nft","-a","list","ruleset"])
    if p and p.returncode==0:
        txt=p.stdout
        print("nft_rules_present="+str(len(txt.splitlines())))
        for port in ("443","18443"):
            print(f"nft_port_{port}_mentions="+str(len(re.findall(rf'\b{port}\b',txt))))
    else:
        print("nft_inspect=UNAVAILABLE")

def output_rule_summary():
    for table in ("raw","mangle","nat","filter","security"):
        p=run(["iptables","-w","-t",table,"-S","OUTPUT"])
        if not p or p.returncode:
            print(f"output_{table}_inspection=UNAVAILABLE")
            continue
        print(f"output_{table}_inspection=OK")
        lines=[line for line in p.stdout.splitlines() if line.startswith("-A ")]
        print(f"output_{table}_rules={len(lines)}")
        for i,line in enumerate(lines[:80],1):
            action=re.search(r"(?:-j|--jump)\\s+(\\S+)",line)
            target=action.group(1) if action else "CONTINUE"
            sport443=bool(re.search(r"--sport\\s+443\\b",line))
            dport443=bool(re.search(r"--dport\\s+443\\b",line))
            queue=bool(re.search(r"--queue-num\\s+",line))
            mark="MARK" in line or "--mark" in line
            verdict=target in ("DROP","REJECT","NFQUEUE","MARK","CONNMARK","TPROXY")
            if sport443 or dport443 or queue or mark or verdict:
                print(f"output_{table}_rule_{i}=target:{target},sport443:{str(sport443).lower()},"
                      f"dport443:{str(dport443).lower()},queue:{str(queue).lower()},"
                      f"mark:{str(mark).lower()},source_scoped:{str(' -s ' in line).lower()}")
    p=run(["nft","list","ruleset"])
    if p and p.returncode==0:
        print("nft_output_explicit_sport443="+str(len(re.findall(r"tcp\\s+sport\\s+443\\b",p.stdout))))
        print("nft_output_drop_tokens="+str(len(re.findall(r"\\bdrop\\b",p.stdout))))

def host_checks():
    for p in ("/run/systemd/system","/proc/net/netfilter/nfnetlink_queue"):
        print("path_"+p.replace("/","_")+"="+str(pathlib.Path(p).exists()).lower())
    cp=run(["dpkg-query","-W","-f=${Status}","libnetfilter-queue1"])
    print("native_nfq_package_installed="+str(bool(cp and cp.returncode==0 and cp.stdout.strip()=="install ok installed")).lower())
    print("network_policy_audit=READ_ONLY_COMPLETE")

if __name__=="__main__":
    owner_summary()
    firewall_summary()
    output_rule_summary()
    host_checks()
