#!/usr/bin/env python3
"""One-time sanitized read-only production WireGuard migration preflight."""
import json,sys,datetime,subprocess,pathlib,re,socket,os,configparser
role=sys.argv[1]
def emit(k,v):
    print("AWG_MIGRATION_"+role+"_"+k+"="+json.dumps(v,ensure_ascii=False,sort_keys=True),flush=True)
def run(*args,timeout=7):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
        return p.returncode,p.stdout.strip()
    except Exception as e:return 254,type(e).__name__
def safe(s):
    s=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<ip>',s)
    s=re.sub(r'\b[A-Za-z0-9+/]{40,}={0,2}\b','<redacted>',s)
    return s[:250]
emit("UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
p=pathlib.Path("/etc/wireguard/tg-relay.conf")
if p.is_file():
    body=p.read_text(errors="replace")
    sections=re.split(r'(?m)^\s*\[([^]]+)\]\s*$',body)
    info={"exists":True,"bytes":len(body),"mode":oct(p.stat().st_mode&0o777)}
    for sec,b in zip(sections[1::2],sections[2::2]):
        vals={}
        for row in b.splitlines():
            if "=" not in row or row.lstrip().startswith(("#",";")):continue
            key,value=[z.strip() for z in row.split("=",1)]
            if key.lower() in ("privatekey","presharedkey","publickey"):
                vals[key]="present"
            elif key.lower() in ("postup","postdown","preup","predown"):
                v=value.lower()
                vals.setdefault(key,[]).append({"length":len(value),
                  "has_mark":"mark" in v,"has_route":"route" in v,"has_iptables":"iptables" in v,
                  "has_wg":bool(re.search(r'\bwg\b',v)),
                  "has_nft":"nft" in v})
            elif key.lower() in ("allowedips","address","mtu","table","listenport","endpoint","fwmark","persistentkeepalive","saveconfig"):
                vals[key]=value
            else:vals[key]="present_or_nonstandard"
        info.setdefault("sections",[]).append({"section":sec, "keys":vals})
    emit("ORIGINAL_CONFIG_SHAPE",info)
for title,args in (
  ("AWG_UNIT",("systemctl","show","wg-quick@tg-relay.service","--property=ActiveState,SubState,FragmentPath,UnitFileState,ExecMainPID")),
  ("IP_RULE",("ip","-4","rule","show")),
  ("TABLE_51820",("ip","-4","route","show","table","51820")),
  ("MAIN_TUNNEL",("ip","-4","route","show","dev","tg-relay")),
  ("PEER_ROUTE",("ip","-4","route","get","10.66.77.1" if role=="RU" else "10.66.77.2")),
  ("MARK_ROUTE",("ip","-4","route","get","1.1.1.1","mark","0x77")),
  ("WG_LINK",("ip","-j","-s","-d","link","show","dev","tg-relay")),
  ("WG_LATEST_HANDSHAKE",("wg","show","tg-relay","latest-handshakes")),
  ("WG_PORT",("wg","show","tg-relay","listen-port")),
  ("WG_ALLOWED",("wg","show","tg-relay","allowed-ips")),
  ("FORWARD",("sysctl","-n","net.ipv4.ip_forward")),
):
    rc,out=run(*args)
    if title=="WG_LINK":
        try:
            j=json.loads(out)[0];emit(title,{"rc":rc,"mtu":j.get("mtu"),"kind":j.get("linkinfo",{}).get("info_kind"),"stats":j.get("stats64") or j.get("stats")})
        except:emit(title,{"rc":rc,"error":"link_parse"})
    elif title=="WG_LATEST_HANDSHAKE":
        e=[int(x.split()[-1]) for x in out.splitlines() if x.split() and x.split()[-1].isdigit()]
        emit(title,{"age_sec":min([max(0,int(datetime.datetime.now().timestamp())-v) for v in e if v>0],default=None)})
    elif title=="WG_ALLOWED":emit(title,{"rc":rc,"allowed":[x.split("\t")[-1] for x in out.splitlines()[:3]]})
    elif title in ("IP_RULE","TABLE_51820","MAIN_TUNNEL","PEER_ROUTE","MARK_ROUTE","AWG_UNIT","FORWARD","WG_PORT"):
        emit(title,{"rc":rc,"lines":[safe(x) for x in out.splitlines()][:25]})
for name,args in (
  ("NAT",("iptables","-t","nat","-S")),
  ("MANGLE",("iptables","-t","mangle","-S")),
  ("FILTER",("iptables","-S")),
  ("IPTABLES_RAW",("iptables","-t","raw","-S")),
  ("NFT",("nft","-a","list","ruleset")),
  ("SYSTEMD_UNITS",("systemctl","list-units","--all","--plain","--no-legend")),
):
    rc,out=run(*args,timeout=10)
    tokens=("tg-relay","10.66.77.","51820","0x77","MASQUERADE","SNAT","FORWARD","mneby-awg","mnebydns-youtube")
    subset=[safe(x) for x in out.splitlines() if any(t.lower() in x.lower() for t in tokens)]
    emit(name,{"rc":rc,"match_count":len(subset),"sample":subset[:33]})
emit("DONE",True)
