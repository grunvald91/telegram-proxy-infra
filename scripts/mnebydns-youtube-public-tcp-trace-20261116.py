#!/usr/bin/env python3
"""Read-only RU->DE public media TLS trace; no packet payloads, peer logs, or persistent state."""
import collections
import concurrent.futures
import datetime
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time

DE = "89.125.90.101"
RU = "188.120.254.223"
PRIVATE_DE = "10.66.77.1"
HOSTS = ("www.youtube.com", "rr1---sn-gxuo03g-ig3s.googlevideo.com")
MODE = sys.argv[1] if len(sys.argv) > 1 else None
assert MODE in ("capture-de", "capture-ru", "client-ru", "client-runner", "read-ru", "read-de")

def command(args, timeout=8):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {"ok":p.returncode == 0, "text":p.stdout.strip()[:2000]}
    except (OSError, subprocess.TimeoutExpired):
        return {"ok":False}

def route(ip):
    r=command(["ip","-j","route","get",ip],timeout=5)
    if not r["ok"]:return {"available":False}
    try:
        x=json.loads(r["text"])[0]
        return {"available":True,"dev":x.get("dev"),"gateway":x.get("gateway"),"src_is_expected":x.get("prefsrc") in (DE,RU)}
    except Exception:return {"available":False}

def tls(ip, hostname, timeout=6):
    t=time.monotonic()
    try:
        with socket.create_connection((ip,443),timeout=timeout) as raw:
            raw.settimeout(timeout)
            tcp_ms=round((time.monotonic()-t)*1000)
            with ssl.create_default_context().wrap_socket(raw,server_hostname=hostname) as secure:
                return {"ok":bool(secure.getpeercert()),"tcp_ms":tcp_ms,"total_ms":round((time.monotonic()-t)*1000),"protocol":secure.version()}
    except Exception as e:
        return {"ok":False,"error":type(e).__name__,"total_ms":round((time.monotonic()-t)*1000)}
def probe_client():
    paths=[("DE_PUBLIC",DE)]
    if MODE=="client-ru":paths.extend([("DE_PRIVATE",PRIVATE_DE),("RU_PUBLIC",RU)])
    if MODE=="client-runner":paths.append(("RU_PUBLIC",RU))
    jobs=[(p,ip,h) for p,ip in paths for h in HOSTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results=list(pool.map(lambda x:{"path":x[0],"host_type":"youtube_web" if x[2]==HOSTS[0] else "googlevideo_cdn",**tls(x[1],x[2])},jobs))
    print(json.dumps({"mode":MODE,"read_only":True,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"results":results}),flush=True)
def capture():
    # Ethernet IPv4/TCP only. Match only RU public and DE public port 443.
    deadline=time.monotonic()+23
    sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
    sock.settimeout(.35)
    flows=collections.defaultdict(lambda:{"syn":0,"synack":0,"client_data_packets":0,"client_data_bytes":0,"clienthello_first_record":0,"server_data_packets":0,"server_data_bytes":0,"rst":0,"fin":0,"interfaces":set()})
    seen=set();matching_packets=0
    while time.monotonic()<deadline:
        try:
            b,addr=sock.recvfrom(20480)
        except socket.timeout:continue
        if len(b)<54 or b[12:14]!=b"\x08\x00":continue
        ihl=(b[14]&15)*4
        off=14+ihl
        if len(b)<off+20 or b[23]!=6:continue
        src,dst=socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34])
        sport,dport=struct.unpack("!HH",b[off:off+4])
        inbound=(src==RU and dst==DE and dport==443)
        outbound=(src==DE and dst==RU and sport==443)
        if not(inbound or outbound):continue
        flags=b[off+13]
        tcp_hlen=(b[off+12]>>4)*4
        if tcp_hlen<20 or len(b)<off+tcp_hlen:continue
        payload=b[off+tcp_hlen:]
        seq=struct.unpack("!I",b[off+4:off+8])[0]
        # De-duplicate repeated capture of same skb across any/bridge interfaces.
        key=(src,dst,sport,dport,seq,flags,len(payload))
        if key in seen:continue
        seen.add(key);matching_packets+=1
        flow=flows[sport if inbound else dport]
        flow["interfaces"].add(addr[0])
        if flags&4:flow["rst"]+=1
        if flags&1:flow["fin"]+=1
        if inbound:
            if flags&2:flow["syn"]+=1
            if payload:
                flow["client_data_packets"]+=1
                flow["client_data_bytes"]+=len(payload)
                if len(payload)>6 and payload[0]==22 and payload[5]==1:flow["clienthello_first_record"]+=1
        else:
            if flags&18==18:flow["synack"]+=1
            if payload:
                flow["server_data_packets"]+=1
                flow["server_data_bytes"]+=len(payload)
    sock.close()
    # No IP/port identifiers, no payloads or client data in artifact.
    values=[{"syn":v["syn"],"synack":v["synack"],"client_data_packets":v["client_data_packets"],"client_data_bytes":v["client_data_bytes"],"clienthello_first_record":v["clienthello_first_record"],"server_data_packets":v["server_data_packets"],"server_data_bytes":v["server_data_bytes"],"rst":v["rst"],"fin":v["fin"],"interfaces":sorted(v["interfaces"])} for v in flows.values()]
    print(json.dumps({"mode":MODE,"read_only":True,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"window_seconds":23,"matching_packets":matching_packets,"matching_flows":len(flows),"metadata_only":True,"flows":values}),flush=True)

def inspect():
    result={"mode":MODE,"read_only":True,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "route_to_remote_public":route(RU if MODE=="read-de" else DE),
            "route_to_tunnel_peer":route("10.66.77.2" if MODE=="read-de" else PRIVATE_DE)}
    commands={"rp_filter": ["sysctl","-n","net.ipv4.conf.all.rp_filter"],
             "tcp_mtu_probing":["sysctl","-n","net.ipv4.tcp_mtu_probing"],
             "tcp_ecn":["sysctl","-n","net.ipv4.tcp_ecn"]}
    for key,argv in commands.items():
        x=command(argv);result[key]=x.get("text") if x["ok"] else "unavailable"
    # Filter summary, no raw rules, source identities or configuration content.
    nft=command(["nft","-j","list","ruleset"],timeout=9)
    if nft["ok"]:
        try:
            # No client addresses or secrets printed.
            full=subprocess.run(["nft","-j","list","ruleset"],capture_output=True,text=True,timeout=9)
            arr=json.loads(full.stdout).get("nftables",[])
            suspects=[]
            for row in arr:
                rule=row.get("rule")
                if not rule:continue
                t=json.dumps(rule.get("expr",[]),separators=(",",":"))
                if any(k in t for k in ('"dport"','"sport"','"saddr"','"daddr"','"dnat"','"tproxy"','"reject"','"notrack"')) and ("443" in t or DE in t or RU in t):
                    actions=[k for k in ("dnat","snat","reject","tproxy","notrack","drop","queue","redirect","masquerade") if '"'+k+'"' in t]
                    suspects.append({"table":rule.get("table"),"chain":rule.get("chain"),"actions":actions,
                                     "tcp443_literal":bool(re.search(r'\b443\b',t)),"rule_handle":rule.get("handle")})
            result["network_rules_matching_443_summary"]=suspects[:80]
            result["network_rules_total"]=len(arr)
        except Exception as e:result["nft_error"]=type(e).__name__
    print(json.dumps(result),flush=True)
if MODE in ("capture-de","capture-ru"):capture()
elif MODE in ("client-ru","client-runner"):probe_client()
else:inspect()
