#!/usr/bin/env python3
"""Read-only privacy-preserving audit of the actual DE89 SmartDNS runtime.
No secrets, IP addresses of users, raw DNS labels, certificate key content,
or database rows are printed.
"""
import collections,datetime,hashlib,json,os,pathlib,re,subprocess,sys,time,ssl,socket,struct

ROLE=sys.argv[1]
def out(k,v):print("AUDIT_DNS_"+ROLE+"_"+k+"="+json.dumps(v,sort_keys=True,ensure_ascii=False),flush=True)
def run(args,sec=12):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=sec)
        return p.stdout,p.returncode
    except Exception:return "",999
def meta(path):
    f=pathlib.Path(path)
    if not f.is_file() or f.is_symlink():return {"exists":False}
    b=f.read_bytes(); m=f.stat()
    return {"exists":True,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),
            "mtime_utc":datetime.datetime.fromtimestamp(m.st_mtime,datetime.timezone.utc).isoformat()}
def services():
    names=("mnebydns-dot.service","mnebydns-personal-sni-stream.service",
           "mnebydns-personal-sni-redirect.service","mnebydns-personal-sni-watch.service",
           "mnebydns-personal-sni-watch.timer","mnebydns-vpn-dot-selfroute-20261115.service",
           "mnebydns-vpn-dot-selfroute-autorevert-20261115.timer",
           "mnebydns-googlepilot.service","nginx.service","mnebyvpn-vpn-provisioner.service")
    for name in names:
        s,_=run(["systemctl","show",name,"--no-pager","-p","ActiveState","-p","SubState","-p","UnitFileState","-p","NRestarts","-p","ExecMainStartTimestamp"],6)
        d={}
        for line in s.splitlines():
            if "=" in line:
                k,v=line.split("=",1)
                if k in ("ActiveState","SubState","UnitFileState","NRestarts","ExecMainStartTimestamp"):d[k]=v
        out("SERVICE_"+name,d)
def live_dns():
    p=pathlib.Path("/opt/mnebydns-dot/Corefile")
    out("COREFILE",meta(str(p)))
    if p.is_file():
        b=p.read_text(errors="replace")
        lines=b.splitlines()
        out("COREFILE_SHAPE",{
            "lines":len(lines),
            "tls853":bool(re.search(r"tls://\.?:853",b)),
            "bind_public":bool(re.search(r"\bbind\s+89\.125\.90\.101",b)),
            "reload":bool(re.search(r"(?m)^\s*reload\b",b)),
            "cache_directives":len(re.findall(r"(?m)^\s*cache\b",b)),
            "forward_directives":len(re.findall(r"(?m)^\s*forward\b",b)),
            "rewrite_directives":len(re.findall(r"(?m)^\s*rewrite\b",b)),
            "template_directives":len(re.findall(r"(?m)^\s*template\b",b)),
            "hosts":len(re.findall(r"(?m)^\s*[a-z0-9*.-]+(?:\s+[a-z0-9.-]+)*\s*$",b)),
            "zone_header_count":len(re.findall(r"(?m)^[a-z0-9*.:{} ]+\{\s*$",b)),
            "forward_self_to_853":bool(re.search(r"(?m)^\s*forward\s+\.\s+(?:tls://)?(?:89\.125\.90\.101|127\.0\.0\.1):853\b",b)),
        })
    cp=pathlib.Path("/opt/mnebydns-stable-checkpoints/1794520280/dns.stable")
    out("PRE13_COREFILE",meta(str(cp)))
    if p.is_file() and cp.is_file():
        old=cp.read_text(errors="replace")
        new=p.read_text(errors="replace")
        def extract(data):
            return {"reload":bool(re.search(r"(?m)^\s*reload\b",data)),
                    "templates":len(re.findall(r"(?m)^\s*template\b",data)),
                    "forward":len(re.findall(r"(?m)^\s*forward\b",data))}
        out("COREFILE_PRE13_VS_CURRENT",{"same_bytes":p.read_bytes()==cp.read_bytes(),"old":extract(old),"new":extract(new)})
def sni():
    p=pathlib.Path("/etc/mnebydns/personal-sni/nginx.conf")
    out("SNI_CONFIG",meta(str(p)))
    if p.is_file():
        t=p.read_text(errors="replace")
        out("SNI_ROUTER_SHAPE",{
            "ssl_preread":bool(re.search(r"(?m)^\s*ssl_preread\s+on\s*;",t)),
            "listener8854":bool(re.search(r"(?m)^\s*listen\s+0\.0\.0\.0:8854\s*;",t)),
            "fallback_core853":bool(re.search(r"(?m)^\s*default\s+89\.125\.90\.101:853\s*;",t)),
            "personal_ru8856":bool(re.search(r"\b10\.66\.77\.2:8856\s*;",t)),
            "personal_ru8853":bool(re.search(r"\b10\.66\.77\.2:8853\s*;",t)),
            "timeout":re.findall(r"(?m)^\s*proxy_(?:connect_)?timeout\s+[0-9a-z]+;",t)[:3],
            "personal_regex_12":bool(re.search(r"\[a-z0-9\]\{12\}",t)),
            "personal_nonregex_map_rules":len(re.findall(r"(?m)^\s*[a-z0-9.-]+\s+\d+\.\d+\.\d+\.\d+:\d+;",t))
        })
    files=["/usr/local/sbin/mnebydns-personal-sni-watch",
           "/opt/mnebydns-vpn-dot-selfroute-20261115/manage.sh",
           "/etc/systemd/system/mnebydns-personal-sni-stream.service",
           "/etc/systemd/system/mnebydns-personal-sni-redirect.service",
           "/etc/systemd/system/mnebydns-personal-sni-watch.service",
           "/etc/systemd/system/mnebydns-personal-sni-watch.timer",
           "/etc/systemd/system/mnebydns-vpn-dot-selfroute-20261115.service"]
    for path in files:out("FILE_"+path,meta(path))
    nat,_=run(["iptables","-t","nat","-S"],10)
    flt,_=run(["iptables","-S"],10)
    out("NAT",{
        "prerouting_853_to_8854":sum("PREROUTING" in x and "--dport 853" in x and "--to-ports 8854" in x for x in nat.splitlines()),
        "output_853_to_8854":sum("OUTPUT" in x and "--dport 853" in x and "--to-ports 8854" in x for x in nat.splitlines()),
        "output_specific_user":sum("OUTPUT" in x and "--uid-owner" in x and "--dport 853" in x for x in nat.splitlines()),
        "external_8854_drop":sum("INPUT" in x and "--dport 8854" in x and "-j DROP" in x for x in flt.splitlines())})
    nginx,_=run(["ss","-H","-lntp"])
    values={}
    for port in (853,8854,1853,8443,18943):
        matches=[x for x in nginx.splitlines() if len(x.split())>3 and x.split()[3].endswith(":"+str(port))]
        owners=sorted({"coredns" if "coredns" in x else "nginx" if "nginx" in x else "xray" if "xray" in x else "other" for x in matches})
        values[str(port)]={"listeners":len(matches),"owners":owners}
    out("TCP_LISTENERS",values)
    st,_=run(["nginx","-t","-c",str(p)]) if p.is_file() else ("",1)
    out("SNI_NGINX_CONFIG_TEST",st==0)
def watchdog():
    for unit in ("mnebydns-personal-sni-watch.service","mnebydns-personal-sni-redirect.service","mnebydns-dot.service",
                 "mnebydns-personal-sni-stream.service","mnebydns-vpn-dot-selfroute-20261115.service"):
        s,rc=run(["journalctl","-u",unit,"--since","2026-11-13 00:00:00","--no-pager","-o","cat"],15)
        c=collections.Counter()
        for ln in s.splitlines():
            u=ln.upper()
            for term in ("FAILED","FALLBACK","FELL_BACK","HEALTHY","COREDNS_ORIGIN_UNHEALTHY","ROLLBACK","STOPPED","STARTED","RESTART","ERROR","OUT_OF_MEMORY","REFUSED","TIMEOUT"):
                if term in u:c[term]+=1
        out("JOURNAL_"+unit,{"events":len(s.splitlines()),"categories":dict(c)})
    # Include watchdog failure counter but not the lock file or secrets.
    p=pathlib.Path("/run/mnebydns-personal-sni-watch/failure-count")
    if p.is_file():
        t=p.read_text().strip()
        out("WATCHDOG_FAILURE_COUNTER",int(t) if t.isdigit() else "invalid")
def verify():
    # Never collect raw credentials or user queries. This is just an unauthenticated
    # synthetic DNS query to the publicly free resolver.
    def query(ip,port,sni,name,kind):
        dns_labels=b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\x00"
        qid=0x75a1
        q=struct.pack("!HHHHHH",qid,256,1,0,0,0)+dns_labels+struct.pack("!HH",kind,1)
        start=time.monotonic()
        with socket.create_connection((ip,port),timeout=5) as sock:
            sock.settimeout(6)
            with ssl.create_default_context().wrap_socket(sock,server_hostname=sni) as tls:
                tls.sendall(struct.pack("!H",len(q))+q)
                def exact(n):
                    buf=b""
                    while len(buf)<n:
                        z=tls.recv(n-len(buf))
                        if not z:raise RuntimeError("truncated")
                        buf+=z
                    return buf
                length=struct.unpack("!H",exact(2))[0]
                result=exact(length)
                assert result[:2]==q[:2] and len(result)>=12
                return {"rcode":result[3]&15,"answers":int.from_bytes(result[6:8],"big"),
                        "ms":round((time.monotonic()-start)*1000)}
    for dst,ip,port in (("core","89.125.90.101",853),("demux","127.0.0.1",8854)):
        for hostname,type_ in (("www.youtube.com",1),("www.youtube.com",28),
                               ("www.youtube.com",65),("example.org",1),("chatgpt.com",1),
                               ("generativelanguage.googleapis.com",1)):
            try:
                o=query(ip,port,"dns.mnebyvpn.site",hostname,type_)
                out("DOT_"+dst+"_"+hostname.replace(".","_")+"_TYPE"+str(type_),o)
            except Exception as exc:
                out("DOT_"+dst+"_"+hostname.replace(".","_")+"_TYPE"+str(type_),{"error":type(exc).__name__})
    for dst,ip in (("public","89.125.90.101"),("demux","127.0.0.1")):
        try:
            with socket.create_connection((ip,853 if dst=="public" else 8854),timeout=5) as sock:
                with ssl.create_default_context().wrap_socket(sock,server_hostname="aaaaaaaaaaaa.dns.mnebyvpn.site") as tls:
                    out("PERSONAL_TLS_"+dst,{"verified":bool(tls.getpeercert())})
        except Exception as exc:out("PERSONAL_TLS_"+dst,{"error":type(exc).__name__})

out("NOW_UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
if ROLE=="DE89":
    services();live_dns();sni();watchdog();verify()
out("COMPLETE",True)
