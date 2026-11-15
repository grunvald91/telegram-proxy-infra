#!/usr/bin/env python3
"""Read-only comparison of 2026-11-13 00:51 MSK checkpoint with current VPS ports.
Prints only port and routing metadata. No client IPs, credentials or configs.
"""
from __future__ import annotations
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
from collections import Counter

ROLE = sys.argv[1]
CHECKPOINT = pathlib.Path("/opt/mnebydns-stable-checkpoints/1794520280")
PORTS = {443, 853, 8443, 18943, 2053, 9443, 15449, 19444, 56781, 56782, 10443, 51820, 3001, 8794, 1080, 8853}
TAGS = {"listen", "proxy_pass", "upstream", "map", "ssl_preread", "proxy_timeout", "proxy_connect_timeout"}
def emit(k, data):
    print("PORTAUDIT_" + ROLE + "_" + k + "=" + json.dumps(data, ensure_ascii=False, sort_keys=True), flush=True)

def cmd(argv, timeout=9):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.returncode
    except (OSError, subprocess.TimeoutExpired):
        return "", 999

def port_from_addr(s):
    s = s.strip("[]").split("%")[0]
    m = re.search(r":(\d+)$", s)
    return int(m.group(1)) if m else None

def directive_snapshot(path):
    if not path.exists() or path.is_symlink():
        return {"exists":False}
    # Output compact routing metadata only. Never emit full config contents.
    result = []
    for no,line in enumerate(path.read_text(errors="replace").splitlines(),1):
        clean = line.strip().split("#",1)[0].strip()
        if not clean:
            continue
        if re.search(r"(?:pass(?:word)?|secret|private.?key|public.?key|credential|auth|token|cert)", clean, re.I) and not clean.startswith(("proxy_pass","proxy_timeout","proxy_connect_timeout")):
            continue
        lead = clean.split(None,1)[0].rstrip("{")
        if lead not in TAGS and not any(str(p) in clean for p in (8443, 18943, 2053, 15449, 9443, 19444)):
            continue
        if clean.startswith("map ") and "server_name" not in clean:
            continue
        if clean.startswith(("listen ","proxy_pass ","map ","upstream ","ssl_preread ","proxy_timeout ","proxy_connect_timeout ")) or re.match(r"^(?:[0-9a-zA-Z_.-]+|\$\w+|~\*)\s+[^\s]+;\s*$", clean):
            if len(clean)>170: clean = clean[:170]+"..."
            # Suppress potentially huge exact-host lists, keep references to selected routes.
            if lead not in TAGS and not re.search(r"youtube|googlevideo|googleapis|speech|antigravity|18943|2053|8443|15449|9443",clean,re.I):
                continue
            result.append([no,clean])
    return {"exists":True,"line_count":len(path.read_text(errors="replace").splitlines()),"directives":result[:90],"directives_total":len(result)}

def service_status(name):
    raw,_=cmd(["systemctl","show",name,"-p","ActiveState","-p","MainPID","-p","ExecMainStartTimestamp","--no-pager"],5)
    return {k:v.strip() for k,v in (line.split("=",1) for line in raw.splitlines() if "=" in line) if k in {"ActiveState","ExecMainStartTimestamp"}}

def current_listeners():
    result=[]
    for protocol,argv in (("TCP",["ss","-H","-lntp"]),("UDP",["ss","-H","-lnup"])):
        raw,_=cmd(argv,12)
        for line in raw.splitlines():
            fields=line.split()
            if len(fields)<5:continue
            bind=fields[4] if protocol=="UDP" else fields[3]
            port=port_from_addr(bind)
            if port is None:continue
            m=re.search(r'users:\(\("([^"]+)"',line)
            result.append(dict(proto=protocol,bind=bind,port=port,owner=m.group(1) if m else "unknown"))
    return sorted(result,key=lambda x:(x["port"],x["proto"],x["bind"]))

def current_xray():
    out=[]
    for name in ("/etc/xray/config.json","/etc/mnebyvpn/xray-canary.json"):
        p=pathlib.Path(name)
        if not p.is_file():continue
        try:
            j=json.loads(p.read_text())
            row={"config":name,"inbounds":[],"outbound_protocols":[x.get("protocol") for x in j.get("outbounds",[])],
                 "routeStrategy":j.get("routing",{}).get("domainStrategy")}
            for x in j.get("inbounds",[]):
                row["inbounds"].append({"port":x.get("port"),"listen":x.get("listen"),"protocol":x.get("protocol"),
                                        "sniffing":x.get("sniffing")})
            out.append(row)
        except Exception as exc:out.append({"config":name,"error":type(exc).__name__})
    return out

def wg_backups():
    d=pathlib.Path("/etc/wireguard")
    if not d.is_dir():return []
    files=[]
    for p in sorted(d.iterdir()):
        if not p.is_file() or p.is_symlink() or p.stat().st_size > 16000:continue
        if not re.search(r"tg-relay|backup|bak|old|prev",p.name,re.I):continue
        if not re.search(r"\.conf|\.bak|\.old|\.prev|backup",p.name,re.I):continue
        raw=p.read_text(errors="replace")
        lp=re.findall(r"(?im)^\s*ListenPort\s*=\s*(\d+)",raw)
        ep=re.findall(r"(?im)^\s*Endpoint\s*=\s*[^#\s:]+:(\d+)",raw)
        if not lp and not ep:continue
        st=p.stat()
        files.append({"name":p.name,"mtime_utc":dt.datetime.fromtimestamp(st.st_mtime,dt.timezone.utc).isoformat(),
                      "listen_port":lp[:2],"peer_endpoint_port":ep[:2]})
    return files[:35]

def fw_references():
    results=[]
    for tool,argv in (("nft",["nft","list","ruleset"]),("iptables-save",["iptables-save"]),("ip6tables-save",["ip6tables-save"])):
        raw,rc=cmd(argv,15)
        if rc!=0:continue
        refs=[]
        for line in raw.splitlines():
            if not re.search(r"\b(?:8443|18943|2053|853|443|19444|56781|56782)\b",line):continue
            if not re.search(r"redirect|dnat|snat|to-ports|dport|sport",line,re.I):continue
            if any(x in line.lower() for x in ("comment", "set element", "password", "secret")):continue
            # Avoid printing client CIDRs.
            line=re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b","IP",line)
            refs.append(line.strip()[:170])
        results.append({"tool":tool,"rules":refs[:25],"count":len(refs)})
    return results

def journal_port_timeline():
    # Historical events only. No raw journal messages or user data.
    res={}
    for service in ("wg-quick@tg-relay.service","xray.service","mnebyvpn-vpn-provisioner.service"):
        raw,_=cmd(["journalctl","-u",service,"--since","2026-11-12 00:00:00 UTC","--until","2026-11-16 00:00:00 UTC","--no-pager","-o","short-iso"],12)
        days=Counter()
        for line in raw.splitlines():
            if re.match(r"^2026-",line):
                days[line[:10]]+=1
        res[service]={"records_per_day":dict(days)}
    return res

def main():
    emit("UTC",dt.datetime.now(dt.timezone.utc).isoformat())
    if ROLE=="DE89":
        old=CHECKPOINT
        emit("CHECKPOINT",{"timestamp_moscow":dt.datetime.fromtimestamp(1794520280,dt.timezone(dt.timedelta(hours=3))).isoformat(),
                           "nginx":directive_snapshot(old/"nginx.stable"),"proxy":directive_snapshot(old/"proxy.stable")})
        emit("LIVE_NGINX",directive_snapshot(pathlib.Path("/etc/nginx/nginx.conf")))
        emit("LIVE_PROXY",directive_snapshot(pathlib.Path("/etc/mnebydns-googlepilot/nginx.conf")))
        emit("XRAY",current_xray())
    else:
        emit("LIVE_NGINX",directive_snapshot(pathlib.Path("/etc/nginx/nginx.conf")))
    emit("LISTENERS",current_listeners())
    raw,_=cmd(["wg","show","tg-relay","listen-port"])
    emit("WG_LISTEN_PORT",raw.strip())
    raw,_=cmd(["wg","show","tg-relay","endpoints"])
    emit("WG_PEER_PORTS",[port_from_addr(x.split()[-1]) for x in raw.splitlines() if x.split()])
    emit("WG_BACKUP_CANDIDATES",wg_backups())
    emit("FIREWALL_PORT_RULES",fw_references())
    emit("JOURNAL_EVENT_COUNTS",journal_port_timeline())
    for service in ("nginx","xray.service","mnebyvpn-vpn-provisioner.service","wg-quick@tg-relay.service","mnebydns-googlepilot.service"):
        emit("SERVICE_"+service,service_status(service))
    emit("COMPLETE",True)

if __name__=="__main__":
    main()
