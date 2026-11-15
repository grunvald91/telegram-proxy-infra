#!/usr/bin/env python3
"""Read-only paired DNS runtime review. Sanitized metadata only; no subscriber records."""
from __future__ import annotations
import subprocess, pathlib,re,datetime,os,hashlib,json,collections,socket,ssl
role=os.environ.get("AUDIT_ROLE","")
def emit(k,v):print("PAIR_DNS_"+role+"_"+k+"="+json.dumps(v,ensure_ascii=False,sort_keys=True),flush=True)
def run(argv,secs=10):
    try:
        p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=secs)
        return p.stdout,p.returncode
    except Exception:return "",999
emit("UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
if role=="DE89":
    cp=pathlib.Path("/opt/mnebydns-dot/Corefile")
    if cp.is_file():
        lines=cp.read_text(errors="replace").splitlines()
        markers=[l.strip() for l in lines if re.match(r"^\s*template\s",l)]
        emit("COREDNS_TEMPLATES",{
            "count":len(markers),
            "first_shapes":[re.sub(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+","DOMAIN",x[:120],flags=re.I) for x in markers[:8]],
            "type_counts":dict(collections.Counter(" ".join(x.split()[:3]) for x in markers)),
            "duplicate_entire_definition_lines":sum(v-1 for v in collections.Counter(markers).values() if v>1)
        })
    for unit in ("mnebydns-dot.service","mnebydns-personal-sni-watch.service","mnebydns-personal-sni-stream.service"):
        t,rc=run(["journalctl","-u",unit,"--since","2026-11-13","--no-pager","-o","short-iso"],14)
        interesting=[]
        for l in t.splitlines():
            lo=l.lower()
            if unit=="mnebydns-dot.service" and any(x in lo for x in ("failed","error","reload","restart","start request repeated")):
                categories=[w for w in ("failed","reload","error","restart","permission denied","too many","invalid") if w in lo]
                stamp=l.split(" ",1)[0] if l.startswith("2026-") else ""
                interesting.append({"time":stamp,"categories":categories})
        emit("JOURNAL_"+unit,{"relevant_events":interesting[-22:]})
if role=="RU188":
    state,_=run(["docker","ps","--format","{{.Names}}|{{.Status}}"],12)
    containers=[s.split("|",1) for s in state.splitlines() if "personal-dot" in s or "mnebyvpn" in s]
    emit("RELATED_CONTAINERS",[{"name":s[0],"uptime_state":s[1][:90] if len(s)>1 else ""} for s in containers[:20]])
    for file in ("/etc/mnebydns/personal-dot/policy.json",
                 "/etc/mnebydns/personal-private/policy.json",
                 "/etc/mnebydns/personal-dot/personal-dot-production.ts",
                 "/etc/mnebydns/personal-private/personal-dot-production.ts"):
        p=pathlib.Path(file)
        if p.is_file() and not p.is_symlink():
            data=p.read_bytes()
            emit("FILE",{"file":file,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),
                         "mtime_utc":datetime.datetime.fromtimestamp(p.stat().st_mtime,datetime.timezone.utc).isoformat()})
            if file.endswith(".json"):
                try:
                    j=json.loads(data)
                    emit("POLICY",{"file":file,"count":len(j) if isinstance(j,list) else -1,
                                   "duplicate_entries":len(j)-len(set(j)) if isinstance(j,list) else -1})
                except Exception:emit("POLICY",{"file":file,"parse_error":True})
    s,_=run(["ss","-H","-lntp"],8)
    for port in (8853,8855,8856,8857,853,3001):
        matches=[l for l in s.splitlines() if len(l.split())>3 and l.split()[3].endswith(":"+str(port))]
        emit("LISTEN_"+str(port),{"count":len(matches),
          "owner":sorted(set("node" if "node" in l else "nginx" if "nginx" in l else "other" for l in matches))})
    for port in (8853,8856):
        try:
            with socket.create_connection(("10.66.77.2",port),timeout=4) as sock:
                with ssl.create_default_context().wrap_socket(sock,server_hostname="aaaaaaaaaaaa.dns.mnebyvpn.site") as tls:
                    emit("PERSONAL_TLS_"+str(port),{"valid":bool(tls.getpeercert()),"version":tls.version()})
        except Exception as e:emit("PERSONAL_TLS_"+str(port),{"error":type(e).__name__})
    for port in (8855,8857):
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=3) as sock:
                sock.settimeout(4)
                sock.sendall(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                data=sock.recv(400)
                status=int(data.split(b" ",2)[1])
                emit("HEALTH_"+str(port),{"http_status":status})
        except Exception as exc:emit("HEALTH_"+str(port),{"error":type(exc).__name__})
emit("DONE",True)
