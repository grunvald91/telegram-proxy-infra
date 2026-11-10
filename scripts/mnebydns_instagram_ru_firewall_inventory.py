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
            action=re.search(r"(?:-j|--jump)\s+(\S+)",line)
            target=action.group(1) if action else "CONTINUE"
            sport443=bool(re.search(r"--sport\s+443\b",line))
            dport443=bool(re.search(r"--dport\s+443\b",line))
            queue=bool(re.search(r"--queue-num\s+",line))
            mark="MARK" in line or "--mark" in line
            verdict=target in ("DROP","REJECT","NFQUEUE","MARK","CONNMARK","TPROXY")
            if sport443 or dport443 or queue or mark or verdict:
                print(f"output_{table}_rule_{i}=target:{target},sport443:{str(sport443).lower()},"
                      f"dport443:{str(dport443).lower()},queue:{str(queue).lower()},"
                      f"mark:{str(mark).lower()},source_scoped:{str(' -s ' in line).lower()}")
    p=run(["nft","list","ruleset"])
    if p and p.returncode==0:
        print("nft_output_explicit_sport443="+str(len(re.findall(r"tcp\s+sport\s+443\b",p.stdout))))
        print("nft_output_drop_tokens="+str(len(re.findall(r"\bdrop\b",p.stdout))))

def nft_443_rule_summary():
    p=run(["nft","-a","list","ruleset"])
    if not p or p.returncode:
        print("nft_rule_context=UNAVAILABLE")
        return
    table="unknown"
    chain="unknown"
    hook="unknown"
    for line in p.stdout.splitlines():
        tm=re.search(r"^\s*table\s+(ip|ip6|inet|bridge)\s+(\S+)",line)
        if tm:
            table=tm.group(1)+":"+tm.group(2)
            chain="unknown"
            hook="unknown"
        cm=re.search(r"^\s*chain\s+(\S+)\s*\{",line)
        if cm:
            chain=cm.group(1)
            hook="unknown"
        hm=re.search(r"\bhook\s+(input|output|prerouting|postrouting|forward)\b",line)
        if hm:
            hook=hm.group(1)
        sport443=bool(re.search(r"\btcp\s+sport\s+443\b",line))
        src_match=bool(re.search(r"\b(?:saddr|daddr)\b",line))
        if sport443:
            target=next((x for x in ("drop","reject","accept","return","queue","dnat","snat","redirect","jump")
                         if re.search(r"\b"+x+r"\b",line)), "other")
            print(f"nft_sport443_rule=table:{table},chain:{chain},hook:{hook},target:{target},"
                  f"source_match:{str(src_match).lower()},ct_state:{str('ct state' in line).lower()},"
                  f"mark:{str('mark' in line).lower()}")
        if hook=="output" and re.search(r"\b(drop|reject)\b",line):
            print(f"nft_output_reject_rule=table:{table},chain:{chain},"
                  f"sport443:{str(sport443).lower()},source_scoped:{str(src_match).lower()}")
    print("nft_rule_context=READ_ONLY_COMPLETE")

def nfqws_postrouting_audit():
    p=run(["nft","-a","list","table","inet","telegram_nfqws"])
    if not p or p.returncode:
        print("telegram_nfqws_nft_table=UNAVAILABLE")
        return
    print("telegram_nfqws_nft_table=AVAILABLE")
    # A return verdict is safe as a bypass only if post is the expected
    # postrouting base chain with an ACCEPT policy. Do not print raw rules.
    in_post=False
    for line in p.stdout.splitlines():
        if re.search(r"^\s*chain\s+post\s*\{", line):
            in_post=True
            print("telegram_post_chain_found=true")
        elif in_post and re.search(r"^\s*\}", line):
            in_post=False
        if in_post and "hook postrouting" in line:
            print("telegram_post_hook_postrouting=true")
            tm=re.search(r"\btype\s+(\w+)\s+hook\s+postrouting\b",line)
            print("telegram_post_chain_type="+(tm.group(1) if tm else "unknown"))
            print("telegram_post_policy_accept="+str(bool(re.search(r"\bpolicy\s+accept\s*;",line))).lower())
            match=re.search(r"\bpriority\s+([^;]+)",line)
            print("telegram_post_priority="+(match.group(1).strip().split()[0] if match else "unknown"))
    for line in p.stdout.splitlines():
        if "tcp sport 443" not in line:
            continue
        queue_match=(re.search(r"\bqueue\s+(?:num\s+)?(\d+)",line) or
                     re.search(r"\bqueue\b[^#]*?\bto\s+(\d+)\b",line))
        queue_num=queue_match.group(1) if queue_match else "UNKNOWN"
        print("telegram_nfqws_sport443_queue="+queue_num)
        print("telegram_nfqws_sport443_bypass="+str("bypass" in line).lower())
        print("telegram_nfqws_sport443_has_mark_match="+str("mark" in line).lower())
        print("telegram_nfqws_sport443_has_ctstate="+str("ct state" in line).lower())
        print("telegram_nfqws_sport443_has_ipv4_scope="+str(bool(re.search(r"\bip\s+(?:saddr|daddr)\b",line))).lower())
        print("telegram_nfqws_sport443_has_syn_only="+str("tcp flags" in line).lower())
    proc=pathlib.Path("/proc/net/netfilter/nfnetlink_queue")
    if proc.exists():
        for line in proc.read_text().splitlines():
            cols=line.split()
            if len(cols)>=7:
                print("native_nfqueue_active_id="+cols[0])
                print("native_nfqueue_depth="+cols[2])
                print("native_nfqueue_kernel_dropped="+cols[5])
                print("native_nfqueue_user_dropped="+cols[6])
    p=run(["systemctl","list-units","--all","--no-legend","--no-pager","*nfqws*"])
    if p and p.returncode==0:
        for line in p.stdout.splitlines():
            parts=line.split()
            if parts and "nfqws" in parts[0]:
                print("nfqws_systemd_unit="+parts[0])
                print("nfqws_systemd_active="+str("active" in parts[:4]).lower())
    print("telegram_nfqws_postrouting_audit=READ_ONLY_COMPLETE")

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
    nft_443_rule_summary()
    nfqws_postrouting_audit()
    host_checks()
