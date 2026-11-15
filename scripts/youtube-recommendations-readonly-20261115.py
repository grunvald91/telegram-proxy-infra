#!/usr/bin/env python3
"""Read-only reality check for the five owner-supplied YouTube remedies.
Prints only service configuration classes, exact public test DNS answers,
and bounded transport metrics. No secrets, raw traffic or customer data.
"""
import datetime, json, pathlib, re, socket, ssl, struct, subprocess, sys, time
ROLE=sys.argv[1] if len(sys.argv)>1 else "UNKNOWN"
RU="188.120.254.223"
DE="89.125.90.101"
WG_DE="10.66.77.1"
TARGET="rr1---sn-gxuo03g-ig3s.googlevideo.com"
def emit(key,value):
    print("OWNER5_"+ROLE+"_"+key+"="+json.dumps(value,ensure_ascii=False,sort_keys=True),flush=True)
def cmd(args,timeout=12):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return p.returncode,p.stdout.strip(),p.stderr.strip()[:130]
    except Exception as e:return 255,"",type(e).__name__
def recvall(s,n):
    b=b""
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c:raise EOFError()
        b+=c
    return b
def skipname(b,pos):
    for _ in range(125):
        if pos>=len(b):raise ValueError("dns_truncated")
        length=b[pos];pos+=1
        if length==0:return pos
        if length&0xc0==0xc0:return pos+1
        if length>63:raise ValueError("dns_label")
        pos+=length
    raise ValueError("dns_name_loop")
def dot_query(host,qtype):
    name=b"".join(bytes([len(x)])+x.encode() for x in host.split("."))+b"\0"
    data=struct.pack("!HHHHHH",17331,256,1,0,0,0)+name+struct.pack("!HH",qtype,1)
    with socket.create_connection((DE,853),timeout=5) as s:
        s.settimeout(5)
        with ssl.create_default_context().wrap_socket(s,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(struct.pack("!H",len(data))+data)
            msg=recvall(tls,struct.unpack("!H",recvall(tls,2))[0])
    if len(msg)<12 or msg[:2]!=data[:2]:raise ValueError("dns_id_mismatch")
    rcode=msg[3]&15
    count=struct.unpack_from("!H",msg,6)[0]
    off=skipname(msg,12)+4
    values=[]
    for _ in range(min(count,150)):
        off=skipname(msg,off)
        if off+10>len(msg):break
        rrtype,rrclass,ttl,ln=struct.unpack_from("!HHIH",msg,off);off+=10
        raw=msg[off:off+ln];off+=ln
        if rrtype==1 and ln==4:values.append(socket.inet_ntoa(raw))
        elif rrtype==28 and ln==16:values.append(socket.inet_ntop(socket.AF_INET6,raw))
        elif rrtype==65:values.append("HTTPS_PRESENT")
        elif rrtype==5:values.append("CNAME_PRESENT")
    return dict(rcode=rcode,answer_count=count,answers=values[:15])
emit("TIME_UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
emit("DNS_QUERY_SOURCE","DoT dns.mnebyvpn.site:853 via TLS certificate verification")
for host in ("www.youtube.com","i.ytimg.com",TARGET):
    for qtype,typename in ((1,"A"),(28,"AAAA"),(65,"HTTPS")):
        try:emit("DOT_"+host.replace(".","_")+"_"+typename,dot_query(host,qtype))
        except Exception as e:emit("DOT_"+host.replace(".","_")+"_"+typename,{"error":type(e).__name__})
if ROLE=="DE":
    p=pathlib.Path("/opt/mnebydns-dot/Corefile")
    if p.is_file():
        s=p.read_text(errors="replace")
        emit("CORE_FILE",{"bytes":len(s),"googlevideo_present":"googlevideo" in s.lower(),
            "cache_directives":len(re.findall(r"(?m)^\\s*cache\\b",s)),
            "googlevideo_mentions":len(re.findall("googlevideo",s,re.I)),
            "youtube_mentions":len(re.findall("youtube",s,re.I))})
else:
    p=pathlib.Path("/etc/mnebydns/personal-dot/policy.json")
    if p.is_file():
        s=p.read_text(errors="replace")
        try:j=json.loads(s);count=len(j)
        except:count=-1
        emit("PERSONAL_POLICY",{"entries":count,"googlevideo_present":"googlevideo" in s.lower(),
            "youtube_present":"youtube" in s.lower(),"path":str(p)})
# Observe service listeners and whether INPUT or FORWARD traffic is relevant.
for protocol,args in (("UDP",["ss","-H","-lunp"]),("TCP",["ss","-H","-lntp"])):
    rc,out,_=cmd(args)
    keep=[]
    for l in out.splitlines():
        bits=l.split()
        if len(bits)<5:continue
        local=bits[4] if bits[0] in ("tcp","udp") else bits[3]
        if not any(local.endswith(":"+str(p)) for p in (443,853,19444,56781,56782)):continue
        owner=re.search(r'\(\("([^"]+)"',l)
        keep.append({"local_port":local.rsplit(":",1)[-1],"process":owner.group(1) if owner else "kernel_or_unknown",
          "bind":"wg" if "10.66.77." in local else ("loopback" if "127.0.0.1" in local else "public_or_wildcard")})
    emit("LISTEN_"+protocol,keep[:18])
for name,args in (("IP_RULE",["ip","-4","rule","show"]),
                  ("WG_LINK",["ip","-j","link","show","dev","tg-relay"]),
                  ("WG_ALLOWED",["wg","show","tg-relay","allowed-ips"]),
                  ("WG_HANDSHAKE",["wg","show","tg-relay","latest-handshakes"])):
    rc,out,err=cmd(args)
    if name=="IP_RULE":
        entries=[re.sub(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',"<IP>",x) for x in out.splitlines()]
        emit(name,{"rc":rc,"rules":entries[:24]})
    elif name=="WG_LINK":
        try:
            val=json.loads(out)[0]
            emit(name,{"rc":rc,"mtu":val.get("mtu"),"operstate":val.get("operstate")})
        except:emit(name,{"rc":rc,"error":err})
    elif name=="WG_ALLOWED":
        emit(name,{"rc":rc,"allowed_ips":[x.split("\t",1)[-1] for x in out.splitlines()[:8]]})
    else:
        epochs=[int(x.split()[-1]) for x in out.splitlines() if x.split() and x.split()[-1].isdigit()]
        emit(name,{"rc":rc,"age_sec":min((int(time.time())-e for e in epochs if e>0),default=None)})
for tag,addr in (("PUBLIC_PEER",RU if ROLE=="DE" else DE),
                 ("WG_PEER","10.66.77.2" if ROLE=="DE" else WG_DE)):
    rc,out,_=cmd(["ip","-4","route","get",addr])
    m=re.search(r"\\bdev\\s+(\\S+)",out)
    emit("ROUTE_"+tag,{"rc":rc,"dev":m.group(1) if m else None})
rc,out,err=cmd(["iptables-save"],8)
if rc==0:
    selected=[x for x in out.splitlines() if not x.startswith("#") and
              ("--dport 443" in x or "--dports" in x or "TCPMSS" in x or "MSS" in x or "--sport 443" in x)]
    counts={"input_udp443":0,"forward_udp443":0,"reject_udp443":0,"mss_rules":0,"matching_rules_total":len(selected)}
    sanitized=[]
    for x in selected:
        if "-A INPUT" in x and "-p udp" in x and "--dport 443" in x:counts["input_udp443"]+=1
        if "-A FORWARD" in x and "-p udp" in x and "--dport 443" in x:counts["forward_udp443"]+=1
        if "-j REJECT" in x and "-p udp" in x:counts["reject_udp443"]+=1
        if "TCPMSS" in x:counts["mss_rules"]+=1
        if len(sanitized)<15:
            sanitized.append(re.sub(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',"<IP>",x)[:200])
    emit("IPTABLES",{"counts":counts,"sample":sanitized})
else:emit("IPTABLES",{"rc":rc,"error":err})
rc,out,err=cmd(["nft","-a","list","ruleset"],8)
if rc==0:
    ss=[x.strip() for x in out.splitlines() if
       re.search(r'\\b443\\b|tcp option maxseg|\\bTCPMSS\\b',x,re.I)]
    emit("NFT443",{"matching_lines":len(ss),"sample":[re.sub(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',"<IP>",x)[:190] for x in ss[:18]]})
else:emit("NFT443",{"rc":rc,"error":err})
# Only RU probes: compare publicly routed ICMP and inner WireGuard with identical payload.
if ROLE=="RU":
    for tag,host in (("PUBLIC",DE),("WG",WG_DE)):
        rc,out,err=cmd(["ping","-n","-q","-M","do","-c","12","-i","0.3","-s","1200","-W","1",host],12)
        match=re.search(r"(\\d+) packets transmitted, (\\d+) received, ([\\d.]+)% packet loss",out)
        emit("PING_"+tag,{"rc":rc,"sent":int(match.group(1)) if match else None,
          "recv":int(match.group(2)) if match else None,
          "loss_pct":float(match.group(3)) if match else None,
          "error":err if not match else None})
emit("COMPLETE",True)
