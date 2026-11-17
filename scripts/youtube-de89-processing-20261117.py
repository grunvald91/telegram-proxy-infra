#!/usr/bin/env python3
"""Bounded DE89-only processing/error audit; no configuration writes."""
import collections, hashlib, json, pathlib, re, subprocess, time

def run(args, timeout=15):
    try:
        p=subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode,p.stdout,p.stderr
    except (OSError,subprocess.TimeoutExpired) as e:
        return -1,"",type(e).__name__
def emit(k,v): print(k+"="+json.dumps(v,sort_keys=True),flush=True)
def family(s):
    for f in ["googlevideo.com","googleapis.com","ytimg.com","gstatic.com","youtube.com"]:
        if f in s: return f
    return "other"
def scrub(s):
    s=re.sub(r"https?://[^\s\"']+","<url>",s)
    s=re.sub(r"[A-Za-z0-9_-]+\.dns\.mnebyvpn\.site","<owner-label>",s)
    s=re.sub(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])","<ip>",s)
    s=re.sub(r"\b[a-fA-F0-9]{32,}\b","<hex>",s)
    return s[:700]

emit("DE89_ONLY",True)
configs=["/etc/nginx/nginx.conf","/etc/mnebydns-googlepilot/nginx.conf"]
before={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in configs}
logs={}
for path in configs:
    rc,out,err=run(["nginx","-T","-c",path])
    emit("NGINX_PARSE",{"path":path,"exit":rc,"sha":before[path]})
    directives=[]
    for line in out.splitlines():
        if re.match(r"\s*(preread_timeout|preread_buffer_size|proxy_buffer_size|proxy_timeout|proxy_connect_timeout|resolver_timeout|resolver|tcp_nodelay|proxy_socket_keepalive|ssl_preread|proxy_pass|listen|error_log|access_log)\s",line):
            directives.append(scrub(line.strip()))
    emit("PROCESSING_DIRECTIVES",{"path":path,"directives":directives})
    for name in re.findall(r"\berror_log\s+(/[^;\s]+)",out):
        p=pathlib.Path(name)
        if p.is_file():
            with p.open('rb') as f:
                size=p.stat().st_size;f.seek(max(0,size-8*1024*1024))
                logs[name]=f.read().decode('utf-8','replace').splitlines()[-10000:]
for unit in ["nginx","mnebydns-googlepilot"]:
    rc,out,_=run(["journalctl","-u",unit,"--since","24 hours ago","--no-pager","-n","5000","-o","cat"])
    logs["journal:"+unit]=out.splitlines()
patterns={"dns_resolution":r"resolv|could not be resolved|no resolver", "timeout":r"timed out|timeout",
          "connect_failure":r"connect\(\) failed|no live upstream|network is unreachable|no route to host",
          "preread_failure":r"preread|client sent invalid|buffer.*small",
          "capacity":r"worker_connections|too many open files|cannot allocate|no buffer space",
          "reset":r"reset by peer|broken pipe", "closed":r"prematurely closed|client closed"}
for name,lines in logs.items():
    counts=collections.Counter();samples=[]
    for line in lines:
        cats=[k for k,p in patterns.items() if re.search(p,line,re.I)]
        for cat in cats: counts[cat+":"+family(line)]+=1
        if cats and "googlevideo.com" in line: samples.append(scrub(line))
    emit("ERROR_LOG_SUMMARY",{"source":name,"lines_examined":len(lines),"counts":dict(counts),"googlevideo_samples":samples[-12:]})
rc,out,_=run(["ss","-Hnt","state","established","(","sport","=",":443","or","sport","=",":15449",")"])
rows=[]
for line in out.splitlines():
    parts=line.split()
    if len(parts)>=2:
        try: rows.append((int(parts[0]),int(parts[1])))
        except ValueError: pass
emit("STREAM_QUEUE_SUMMARY",{"connections":len(rows),"recv_queued":sum(x[0] for x in rows),"send_queued":sum(x[1] for x in rows),"max_recv":max([x[0] for x in rows],default=0),"max_send":max([x[1] for x in rows],default=0)})
for p in ["/proc/net/netfilter/nfnetlink_queue","/proc/sys/net/ipv4/tcp_mtu_probing","/proc/sys/net/ipv4/tcp_syncookies"]:
    if pathlib.Path(p).exists(): emit("KERNEL_STATE",{"path":p,"value":pathlib.Path(p).read_text().strip()})
after={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in configs}
if before!=after: raise RuntimeError("CONFIG_CHANGED_DURING_AUDIT")
emit("PRODUCTION_CONFIG_UNCHANGED",True)
