#!/usr/bin/env python3
"""Only TCP metadata by peer cohort. No customer IPs, names or packets emitted."""
import collections, datetime, hashlib, ipaddress, os, re, subprocess, sys, time
role=sys.argv[1]; salt=os.urandom(16)
def cmd(xs):
    try:return subprocess.check_output(xs,stderr=subprocess.DEVNULL,text=True,timeout=10)
    except Exception:return ""
def n(s,k):
    m=re.search(r"(?<!\w)"+re.escape(k)+r":(\d+)",s)
    return int(m.group(1)) if m else 0
def peerclass(ip):
    try:
        addr=ipaddress.ip_address(ip.rsplit(":",1)[0].strip("[]").split("%")[0])
        if isinstance(addr,ipaddress.IPv6Address) and addr.ipv4_mapped:addr=addr.ipv4_mapped
    except ValueError:return "UNPARSED"
    if str(addr)=="188.120.254.223":return "RU188_PUBLIC"
    if str(addr)=="89.125.90.101":return "DE89_SELF_PUBLIC"
    if addr.is_loopback:return "LOCAL_LOOPBACK"
    if addr.version==4 and addr in ipaddress.ip_network("10.66.77.0/24"):return "WG_PRIVATE"
    if addr.is_private:return "OTHER_PRIVATE"
    return "OTHER_PUBLIC"
def snapshot():
    result={};key=None
    for line in cmd(["ss","-Htin"]).splitlines():
        sp=line.split()
        if len(sp)>=5 and sp[0]=="ESTAB":
            local,remote=sp[3:5]
            kind="DE_OR_RU_INBOUND_443" if local.endswith(":443") else "OUTBOUND_443" if remote.endswith(":443") else None
            key=hashlib.sha256(salt+(local+"|"+remote).encode()).hexdigest()[:12] if kind else None
            if key:result[key]={"cohort":peerclass(remote if kind.startswith("DE_OR") else remote),"kind":kind,
                "sent":0,"received":0,"retrans":0,"rto":0,"rtt":"","pmtu":0,"unacked":0}
        elif key and ("bytes_sent:" in line or "rtt:" in line):
            r=result[key]
            for field in ("bytes_sent","bytes_received","bytes_retrans","rto","pmtu","unacked"):
                z=n(line,field)
                r[{"bytes_sent":"sent","bytes_received":"received","bytes_retrans":"retrans"}.get(field,field)]=z
            m=re.search(r"\brtt:([0-9.]+)/",line)
            r["rtt"]=m.group(1) if m else ""
            key=None
    return result
def report(k,v):
    print("COHORT_"+role+"_"+k+"="+str(v),flush=True)
report("START_UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
a=snapshot();time.sleep(14);b=snapshot()
summ=collections.defaultdict(lambda:collections.Counter())
items=[]
for key,after in b.items():
    before=a.get(key)
    if not before:continue
    sent=max(0,after["sent"]-before["sent"])
    received=max(0,after["received"]-before["received"])
    retry=max(0,after["retrans"]-before["retrans"])
    bucket=after["kind"]+"_"+after["cohort"]
    count=summ[bucket];count["matched"]+=1;count["sent"]+=sent;count["received"]+=received;count["retrans"]+=retry
    if retry>0:count["retransmitting_flows"]+=1
    if sent<2000 and retry>2000:count["stalled"]+=1
    if retry>0:
        items.append((retry,key,bucket,sent,received,after["rtt"],after["rto"],after["pmtu"],after["unacked"]))
for bucket,val in sorted(summ.items()):
    report("GROUP_"+bucket,repr(dict(val)))
for i,item in enumerate(sorted(items,reverse=True)[:12]):report("TOP_RETRANS_"+str(i),repr(item))
report("END_UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
report("COMPLETE","TRUE")
