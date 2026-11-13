#!/usr/bin/env python3
"""Read-only anonymous ingress/Telegram port inventory for one existing server.
Never print peer IPs, subscriber secrets or full service config.
"""
import json
import pathlib
import re
import subprocess
import sys

role = sys.argv[1] if len(sys.argv)==2 else "invalid"
assert role in ("ru","de")

def run(*args, timeout=12):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout
    except Exception:
        return 255, ""

def service(name):
    return run("systemctl","is-active","--quiet",name)[0]==0

print("audit_role="+role, flush=True)
for key,name in [("nginx","nginx.service"),("telegram_nfqws","telegram-nfqws.service"),
                 ("telemt","telemt.service"),("ufw","ufw.service")]:
    print("service_"+key+"="+str(service(name)).lower(), flush=True)

code, listeners = run("ss","-H","-lntp")
for port in (443,8443,10443,9470,9443,853):
    matching=[z for z in listeners.splitlines()
              if re.search(r":"+str(port)+r"\s",z)]
    print("tcp_listener_"+str(port)+"="+str(bool(matching)).lower(),flush=True)
    print("tcp_listener_"+str(port)+"_nginx="+str(any("nginx" in z for z in matching)).lower(),flush=True)
    c,out=run("ss","-H","-nt","state","established","sport","=",":"+str(port))
    print("tcp_port_"+str(port)+"_established_count="+str(len(out.splitlines()) if c==0 else -1),flush=True)
code, config=run("nginx","-T",timeout=18)
print("nginx_config_valid="+str(code==0).lower(),flush=True)
# nginx -T splits configuration by original file. Only inspect the stream-related
# files and infer whether 8443 has an explicit proxy backend.
chunks=re.split(r"(?m)^# configuration file ([^:]+):\s*$",config)
for port in (443,8443,10443):
    sites=[]
    for i in range(1,len(chunks)-1,2):
        file=chunks[i]
        if "/streams.d/" not in file:
            continue
        body=chunks[i+1]
        for match in re.finditer(r"(?m)^\s*listen\s+([^\n;]+);",body):
            spec=match.group(1)
            if not re.search(r"(?<!\d)"+str(port)+r"(?!\d)",spec):
                continue
            sites.append((file,body,spec))
    print("stream_listen_"+str(port)+"_configuration_entries="+str(len(sites)),flush=True)
    print("stream_listen_"+str(port)+"_sni_preread="+str(any("ssl_preread on;" in body for _,body,_ in sites)).lower(),flush=True)
    print("stream_listen_"+str(port)+"_proxy_pass_found="+str(any("proxy_pass " in body for _,body,_ in sites)).lower(),flush=True)
    print("stream_listen_"+str(port)+"_wg_target="+str(any(re.search(r"proxy_pass\s+10\.\d+\.\d+\.\d+",body) for _,body,_ in sites)).lower(),flush=True)

# Audit queue scope on the same host without printing server secrets or peer endpoints.
code,nft=run("nft","-j","list","chain","inet","telegram_nfqws","post")
rules=[]
if code==0:
    try:rules=[item["rule"] for item in json.loads(nft).get("nftables",[]) if "rule" in item]
    except Exception:pass
print("nfqueue_chain_exists="+str(code==0).lower(),flush=True)
print("nfqueue_210_rule_count="+str(sum(any("queue" in e and e["queue"].get("num")==210
    for e in r.get("expr",[])) for r in rules)),flush=True)
# Inspect exact stream server blocks and infer backend class without logging addresses.
# Nginx -T includes HTTP vhosts; restrict to stream-related configuration file names
# on RU and inspect any matching server blocks on DE by checking proxy_pass.
def classify(target):
    if not target:return "missing"
    if target.startswith("$"):return "variable"
    if target.startswith("127."):return "loopback"
    if target.startswith("10."):return "private"
    return "other"
for port in (443,8443,10443):
    classes=[]
    for match in re.finditer(r"server\s*\{([^{}]*)\}",config,re.S):
        block=match.group(1)
        if not re.search(r"(?m)^\s*listen\s+(?:[^\s;]*:)?"+str(port)+r"(?:\s|;)",block):
            continue
        target=re.search(r"\bproxy_pass\s+([^;\s]+)",block)
        classes.append(classify(target.group(1) if target else ""))
        if target:
            port_match=re.search(r":(\d+)$",target.group(1))
            print("backend_"+str(port)+"_port="+(port_match.group(1) if port_match else "variable"),flush=True)
    print("backend_"+str(port)+"_class="+(",".join(classes) if classes else "unknown"),flush=True)
try:
    addresses=json.loads(run("ip","-j","-4","address","show")[1])
    import ipaddress
    ip_list=[ipaddress.ip_address(item.get("local"))
             for dev in addresses for item in dev.get("addr_info",[])
             if item.get("family")=="inet" and item.get("local")]
    public=[ip for ip in ip_list if ip.is_global]
    print("global_ipv4_address_count="+str(len(public)),flush=True)
    print("has_dedicated_additional_public_ipv4="+str(len(public)>1).lower(),flush=True)
except Exception:
    print("global_ipv4_address_count=unknown",flush=True)
print("audit_read_only=true",flush=True)
