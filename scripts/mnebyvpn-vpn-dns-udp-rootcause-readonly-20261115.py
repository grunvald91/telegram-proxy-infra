#!/usr/bin/env python3
"""Read-only source attribution for VPN upstream errors, UDP443 allowlist drops and DoT route scope."""
from __future__ import annotations
import collections, datetime, json, os, pathlib, re, subprocess, sys
role=sys.argv[1]
def emit(k,v):print("PATHROOT_"+role+"_"+k+"="+json.dumps(v,ensure_ascii=False,sort_keys=True),flush=True)
def sh(args,timeout=10):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
        return p.stdout,p.returncode
    except Exception:return "",999

def xray_owner():
    p,_=sh(["ps","-eo","pid=,uid=,comm=,args="])
    processes=[]
    for line in p.splitlines():
        spl=line.split(None,3)
        if len(spl)<4 or spl[2]!="xray":continue
        args=spl[3]
        tag="shared" if "/etc/xray/config.json" in args else "vpn-provisioner" if "xray-canary.json" in args else "unknown"
        processes.append({"role":tag,"uid":int(spl[1])})
    emit("XRAY_UIDS",processes)
    f,_=sh(["iptables","-t","nat","-S","OUTPUT"])
    total=0;dns=0
    for l in f.splitlines():
        if l.startswith("-A OUTPUT"):total+=1
        if "853" in l and "8854" in l:dns+=1
    emit("NAT_LOCAL_OUTPUT",{"rules":total,"dns_to_8854_rules":dns})
    f,_=sh(["iptables","-t","nat","-S","PREROUTING"])
    emit("NAT_PUBLIC_PREROUTING_DNS_TO_ROUTER",any("--dport 853" in l and "--to-ports 8854" in l for l in f.splitlines()))
    for unit in ("mnebydns-personal-sni-stream.service","mnebydns-personal-sni-redirect.service","mnebydns-dot.service"):
        f,_=sh(["systemctl","is-active",unit])
        emit("UNIT_"+unit,f.strip())
    p=pathlib.Path("/etc/mnebydns/personal-sni/nginx.conf")
    if p.is_file():
        t=p.read_text(errors="replace")
        emit("PERSONAL_ROUTER",{"default_to_core853":bool(re.search(r"default\\s+89\\.125\\.90\\.101:853\\s*;",t)),
                 "personal_to_ru8856":bool(re.search(r"10\\.66\\.77\\.2:8856\\s*;",t)),
                 "personal_to_old8853":bool(re.search(r"10\\.66\\.77\\.2:8853\\s*;",t)),
                 "bind8854":bool(re.search(r"listen\\s+0\\.0\\.0\\.0:8854\\s*;",t))})

def errors():
    for name in ("nginx","xray.service","mnebyvpn-vpn-provisioner.service"):
        txt,_=sh(["journalctl","-u",name,"--since","-45 min","--no-pager","-o","cat"],13)
        classes=collections.Counter()
        for l in txt.splitlines():
            lo=l.lower()
            for label,rex in (("timeout",r"time.?out"),("failed",r"failed"),("reset",r"reset|broken pipe"),("upstream",r"upstream"),("rejected",r"reject"),("overload",r"buffer|overload"),("cert",r"certificate|handshake")):
                if re.search(rex,lo):classes[label]+=1
        emit("JOURNAL_"+name,dict(classes))
    for name in ("/var/log/nginx/error.log","/var/log/nginx/mnebyvpn-telegram-8443-error.log"):
        p=pathlib.Path(name)
        if not p.exists():continue
        # Only latest log bytes; avoid exposing raw request paths, IP addresses and token.
        try:
            with p.open("rb") as stream:
                stream.seek(0,os.SEEK_END);size=stream.tell();stream.seek(max(0,size-800000));raw=stream.read().decode(errors="replace")
            classes=collections.Counter()
            for l in raw.splitlines()[-800:]:
                low=l.lower()
                if "upstream timed out" in low:classes["upstream_timeout"]+=1
                if "prematurely closed" in low:classes["premature_close"]+=1
                if "no live upstreams" in low:classes["no_upstream"]+=1
                if "broken pipe" in low:classes["broken_pipe"]+=1
                if "connect() failed" in low:classes["connect_failed"]+=1
                if "certificate" in low:classes["certificate"]+=1
            emit("NGINX_LOG_"+p.name,dict(classes))
        except Exception:pass

def media():
    units=("mnebydns-youtube-quic-ru-43612369808.service","mnebydns-youtube-quic-de-43612369808.service","mnebydns-de89-public-quic-20261115.service")
    fields=("rx","to_upstream","upstream_rx","client_tx","admitted","rejected","not_youtube","partial_initial","unreadable_initial","pending_expired","fragmented_admitted","socket_error","emsgsize","undersize","resolve_error")
    for unit in units:
        s,_=sh(["systemctl","is-active",unit])
        if s.strip()!="active":continue
        t,_=sh(["journalctl","-u",unit,"--since","-30 minutes","--no-pager","-o","cat"],13)
        snap=[]
        for l in t.splitlines():
            if not re.search(r"youtube_quic_.*active=",l):continue
            data={k:int(v) for k,v in re.findall(r"\\b([a-z_]+)=(\\d+)\\b",l) if k in fields}
            if data:snap.append(data)
        diff={}
        if snap:
            for field in fields:
                if field in snap[0] and field in snap[-1]:diff[field]=max(0,snap[-1][field]-snap[0][field])
        emit("QUIC_"+unit,{"latest":{k:snap[-1].get(k) for k in fields if k in snap[-1]} if snap else {},"delta":diff,"samples":len(snap)})

emit("UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
if role=="DE89":xray_owner()
errors();media();emit("DONE",True)
