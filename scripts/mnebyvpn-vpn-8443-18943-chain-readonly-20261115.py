#!/usr/bin/env python3
"""Read-only topology proof of HTTPS 8443 to local VPN 18943 and historical config age.
Only route metadata and port/protocol flags are emitted. No secrets or client info.
"""
import subprocess,pathlib,re,sys,json,datetime,hashlib,os
role=sys.argv[1]
def emit(k,v):print("CHAIN_"+role+"_"+k+"="+json.dumps(v,ensure_ascii=False,sort_keys=True),flush=True)
def run(cmd,timeout=8):
    try:
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=timeout)
        return p.stdout if p.returncode==0 else ""
    except Exception:return ""
def mtime(path):
    p=pathlib.Path(path)
    return datetime.datetime.fromtimestamp(p.stat().st_mtime,datetime.timezone.utc).isoformat() if p.is_file() else None
def xray():
    for path in ("/etc/xray/config.json","/etc/mnebyvpn/xray-canary.json"):
        p=pathlib.Path(path)
        if not p.is_file():continue
        try:
            cfg=json.loads(p.read_text())
            emit("XRAY_CONFIG_FILE",{"path":path,"mtime_utc":mtime(path),"sha16":hashlib.sha256(p.read_bytes()).hexdigest()[:16]})
            for i,entry in enumerate(cfg.get("inbounds",[])):
                st=entry.get("streamSettings") or {}
                ws=st.get("wsSettings") or {}
                http=st.get("httpSettings") or {}
                reality=st.get("realitySettings") or {}
                emit("XRAY_INBOUND",{"index":i,"port":entry.get("port"),"listen":entry.get("listen"),"network":st.get("network"),
                    "security":st.get("security"),"ws_path_present":bool(ws.get("path")),"ws_accept_proxy_protocol":ws.get("acceptProxyProtocol"),
                    "http_path_present":bool(http.get("path")),"reality_enabled":bool(reality),"sniffing":bool((entry.get("sniffing") or {}).get("enabled"))})
        except Exception as ex:emit("XRAY_ERROR",type(ex).__name__)
def nginx():
    full=run(["nginx","-T"],17)
    sections=[]
    current=None
    for line in full.splitlines():
        if line.startswith("# configuration file "):
            current=line.removeprefix("# configuration file ").rstrip(":").strip()
            continue
        clean=line.strip()
        if not clean or clean.startswith("#"):continue
        if re.search(r"(?:\blisten\s+.*\b8443\b|\b(?:127\.0\.0\.1|10\.66\.77\.[12]):(?:8443|18943|2053|9443)\b|\bproxy_pass\s+.+\b18943\b|proxy_http_version|proxy_set_header\s+(?:Upgrade|Connection)|\$stream_443_backend|\$direct_mtproxy_backend)",clean,re.I):
            safe=clean
            # Keep port mapping, omit unrelated request paths and upstream credentials.
            if "proxy_pass" in clean and re.search(r"https?://[^;\s]*@",clean):continue
            if len(safe)>190:safe=safe[:190]+"..."
            if re.search(r"password|secret|private_key|authorization|token",safe,re.I):continue
            sections.append({"file":current,"text":safe})
    for row in sections[:75]:emit("NGINX_PORT_LINK",row)
    emit("NGINX_PORT_LINK_COUNT",len(sections))
    files=[]
    for row in sections:
        fname=row.get("file")
        if fname and fname.startswith("/") and pathlib.Path(fname).is_file() and fname not in files:files.append(fname)
    emit("NGINX_CONFIG_FILE_AGES",[{"path":p,"mtime_utc":mtime(p)} for p in files[:15]])
def links():
    s=run(["ss","-Htnp"],10)
    result={}
    for port in (8443,18943,2053):
        counters={"established_local":0,"established_peer":0}
        for line in s.splitlines():
            items=line.split()
            if len(items)<5 or items[0]!="ESTAB":continue
            if items[3].endswith(":"+str(port)):counters["established_local"]+=1
            if items[4].endswith(":"+str(port)):counters["established_peer"]+=1
        result[str(port)]=counters
    emit("SOCKET_COUNTS",result)
def endpoint_connect():
    import socket,time
    for ip,port in ([("89.125.90.101",8443),("89.125.90.101",2053),("89.125.90.101",443)] if role=="RU188" else
                    [("127.0.0.1",18943),("127.0.0.1",8443),("127.0.0.1",15449)]):
        start=time.monotonic()
        try:
            with socket.create_connection((ip,port),timeout=3):
                emit("CONNECT",{"destination":ip+":"+str(port),"status":"TCP_OK","ms":round((time.monotonic()-start)*1000)})
        except OSError as ex:
            emit("CONNECT",{"destination":ip+":"+str(port),"status":type(ex).__name__,"ms":round((time.monotonic()-start)*1000)})
if role=="DE89":xray()
nginx()
links()
endpoint_connect()
emit("COMPLETE",True)
