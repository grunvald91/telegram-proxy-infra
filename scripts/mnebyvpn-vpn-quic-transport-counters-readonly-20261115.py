#!/usr/bin/env python3
"""Read-only, privacy-preserving diagnostics of live VPN transport and UDP/DoT ingress."""
from __future__ import annotations
import collections, datetime, json, os, pathlib, re, statistics, subprocess, sys, time

ROLE = sys.argv[1]
def emit(name, value):
    print("TRANSPORT_"+ROLE+"_"+name+"="+json.dumps(value,ensure_ascii=False,sort_keys=True),flush=True)
def sh(args,sec=10):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=sec)
        return p.stdout, p.returncode
    except Exception:
        return "", 999

def socket_sample():
    txt,rc=sh(["ss","-Htin"],20)
    flow={}
    ident=None
    for line in txt.splitlines():
        fields=line.split()
        if len(fields)>4 and fields[0]=="ESTAB":
            local,remote=fields[3:5]
            def name(addr):
                if re.search(r"[:](8443|18943|2053|15449|443|853)$",addr):
                    return int(addr.rsplit(":",1)[1])
                return None
            port=name(local)
            if port==8443:
                group="8443_public" if local.startswith("89.125.90.101:") else "8443_loopback"
            elif port==18943:group="18943_loopback"
            elif port==2053:group="2053_reality"
            elif port==15449:group="15449_google"
            elif port==443:group="443_server"
            elif port==853:group="853_dot"
            elif name(remote)==443:group="443_egress"
            else:group=None
            ident=(local,remote) if group else None
            if ident:flow[ident]={"group":group,"rtt_ms":None,"sent":0,"received":0,"retrans":0,"unacked":0}
        elif ident and ("rtt:" in line or "bytes_sent:" in line):
            f=flow[ident]
            for key,tcpfield in (("sent","bytes_sent"),("received","bytes_received"),("retrans","bytes_retrans"),("unacked","unacked")):
                m=re.search(r"(?<![A-Za-z])"+tcpfield+r":(\d+)",line)
                if m:f[key]=int(m.group(1))
            r=re.search(r"\brtt:([0-9.]+)/",line)
            if r:f["rtt_ms"]=float(r.group(1))
            ident=None
    return flow

def kernel():
    val,_=sh(["nstat","-az"],9)
    keys={"TcpRetransSegs","TcpExtTCPTimeouts","TcpExtTCPSynRetrans","TcpExtTCPFastRetrans","TcpExtTCPLossProbes","TcpExtTCPLossProbeRecovery","TcpExtTCPBacklogDrop",
          "UdpRcvbufErrors","UdpSndbufErrors","IpOutDiscards","IpInDiscards"}
    k={}
    for l in val.splitlines():
        s=l.split()
        if len(s)>1 and s[0] in keys:
            try:k[s[0]]=int(s[1])
            except ValueError:pass
    return k

def summarize_sockets(before,after):
    stat={}
    for k,v in after.items():
        g=v["group"]
        d=stat.setdefault(g,{"connections":0,"stable":0,"retrans_added":0,"sent_added":0,"received_added":0,"retrans_sockets":0,"rtt_ms_p50":None,"rtt_ms_p95":None})
        d["connections"]+=1
    rtts=collections.defaultdict(list)
    for k,v in after.items():
        g=v["group"];s=stat[g]
        if v["rtt_ms"] is not None:rtts[g].append(v["rtt_ms"])
        if k not in before:continue
        prev=before[k]
        if prev["group"]!=g:continue
        s["stable"]+=1
        # Sequence counters can reset when a socket is reused. Ignore such outliers.
        for item,name in (("retrans","retrans_added"),("sent","sent_added"),("received","received_added")):
            delta=max(0,v[item]-prev[item]);s[name]+=delta
            if item=="retrans" and delta:s["retrans_sockets"]+=1
    for g,vals in rtts.items():
        vals.sort()
        stat[g]["rtt_ms_p50"]=round(statistics.median(vals),2)
        stat[g]["rtt_ms_p95"]=round(vals[max(0,int((len(vals)-1)*.95))],2)
    for g,data in sorted(stat.items()):emit("SOCKET_"+g,data)

def udp_listeners():
    data,_=sh(["ss","-H","-lunp"],9)
    a=[]
    for line in data.splitlines():
        items=line.split()
        if len(items)<4:continue
        port=items[3].rsplit(":",1)[-1]
        if port not in ("443","19444","56781","56782","853","8854"):continue
        m=re.search(r'users:\(\("([^"]+)"',line)
        a.append({"local_port":int(port),"interface_bind_kind":"wg" if items[3].startswith("10.66.") else
                  "public" if items[3].startswith(("89.125.","188.120.")) else "wildcard_or_local",
                  "process":m.group(1) if m else "kernel"})
    emit("UDP_LISTENERS",a)

def service(name):
    ret,_=sh(["systemctl","show",name,"-p","ActiveState","-p","SubState","-p","MainPID","-p","NRestarts","--no-pager"],8)
    d={}
    for ln in ret.splitlines():
        if "=" in ln:
            k,v=ln.split("=",1)
            if k in ("ActiveState","SubState","NRestarts"):d[k]=v
    return d

def quic_logs():
    candidates=("mnebydns-youtube-quic-ru-43612369808.service",
                "mnebydns-youtube-quic-de-43612369808.service",
                "mnebydns-de89-public-quic-20261115.service")
    for unit in candidates:
        svc=service(unit)
        if svc.get("ActiveState")!="active":continue
        data,_=sh(["journalctl","-u",unit,"--since","-30 minutes","--no-pager","-o","cat"],14)
        aggregates=collections.Counter()
        snapshots=0
        first,last=None,None
        for ln in data.splitlines():
            if not any(marker in ln for marker in ("youtube_quic_","quic_","QUIC_")):continue
            metrics={}
            for key,val in re.findall(r"\b([a-z_]+)=(\d+)\b",ln):
                if key in ("rx","tx","to_upstream","upstream_rx","client_tx","socket_error","emsgsize","admitted","rejected","resolve_error","peer_drop","undersize","oversize","expired","flow_open","flow_closed","active"):
                    metrics[key]=int(val)
            if metrics:
                if first is None:first=metrics
                last=metrics;snapshots+=1
        diff={}
        if first and last:
            for k in ("rx","tx","to_upstream","upstream_rx","client_tx","socket_error","emsgsize","admitted","rejected","resolve_error","peer_drop","undersize","oversize","expired"):
                if k in first and k in last:diff[k]=max(0,last[k]-first[k])
        emit("QUIC_LOG_"+unit,{"status":svc,"records":snapshots,"last_counter":last or {},"window_delta":diff})
def nginx_443_socket_state():
    data,_=sh(["ss","-H","-lntp"],8)
    rows=[]
    for ln in data.splitlines():
        p=ln.split()
        if len(p)<4:continue
        port=p[3].rsplit(":",1)[-1]
        if port not in ("443","853","8854","15449","8443","18943","2053","1853"):continue
        m=re.search(r'users:\(\("([^"]+)"',ln)
        rows.append({"port":int(port),"local_class":"public" if p[3].startswith(("89.125.","188.120.")) else
                     "loopback" if p[3].startswith("127.") else "wg" if p[3].startswith("10.66.") else "wildcard",
                     "process":m.group(1) if m else "unknown"})
    emit("TCP_LISTENERS",rows)

emit("UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
emit("WG_HANDSHAKE",sh(["wg","show","tg-relay","latest-handshakes"],6)[0].splitlines() and "present")
udp_listeners();nginx_443_socket_state();quic_logs()
pre=socket_sample();a=kernel();time.sleep(14);post=socket_sample();b=kernel()
summarize_sockets(pre,post)
emit("KERNEL_DELTA",{k:b.get(k,0)-a.get(k,0) for k in sorted(set(a)|set(b)) if b.get(k,0)-a.get(k,0)})
emit("DONE",True)
