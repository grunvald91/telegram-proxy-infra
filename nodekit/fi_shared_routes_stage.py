#!/usr/bin/env python3
"""Stage the shared FI route bundle after real local DNS/SNI canary."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from fi_shared_routes import hostname,covered,render_core,render_nginx,need,FI
from fi_dns_ssh_stage import host,private_dir,read,immutable,command
from fi_dns_origin_canary import COREDNS,HOSTS,read_exact
from fi_dns_metered_dot import valid_answer

ROOT=Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
STATE=ROOT/"dns-auth"
DEST=STATE/"shared-routes"

def dns_query(name,kind):
    qid=secrets.randbits(16)
    q=struct.pack("!HHHHHH",qid,256,1,0,0,0)+b"".join(bytes([len(x)])+x.encode("ascii") for x in name.split("."))+b"\0"+struct.pack("!HH",kind,1)
    with socket.create_connection(("127.0.0.1",18855),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=HOSTS[0]) as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            size=struct.unpack("!H",read_exact(tls,2))[0]
            need(12<=size<=16384,"route_dns_size")
            reply=read_exact(tls,size)
    valid_answer(q,reply)
    _,flags,qd,an,_,_=struct.unpack("!HHHHHH",reply[:12])
    need(flags&15==0 and qd==1,"route_dns_response")
    if kind!=1:
        need(an==0,"alternate_route_not_suppressed")
        return
    need(an==1,"route_A_count")
    # The existing strict DNS parser validated the complete message. Here
    # independently check the sole A record's type and four-byte data.
    off=len(q)
    if reply[off]&0xc0==0xc0:off+=2
    else:
        while reply[off]:off+=1+reply[off]
        off+=1
    rt,cl,_,rdlen=struct.unpack_from("!HHIH",reply,off)
    need(rt==1 and cl==1 and rdlen==4 and reply[off+10:off+14]==socket.inet_aton(FI),"route_A_not_FI")

def proxy_probe(name,allowed):
    try:
        with socket.create_connection(("127.0.0.1",14443),timeout=8) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname=name) as tls:
                need(tls.getpeercert(),"origin_cert_missing")
    except (OSError,ssl.SSLError):
        if not allowed:return
        raise ValueError("allowed_proxy_tls_failed") from None
    need(allowed,"unknown_proxy_sni_accepted")

def stop(child):
    if child.poll() is None:
        child.terminate()
        try:child.wait(5)
        except subprocess.TimeoutExpired:child.kill();child.wait(5)

def startup_diagnostic(name,child,log):
    if child.poll() is None:return
    # Never print raw config/error lines: regex errors can contain the live
    # domain catalog. Classify bounded local logs instead.
    with log.open("rb") as f:
        f.seek(max(0,log.stat().st_size-65536))
        detail=f.read(65536).lower()
    categories=((b"regex pattern too long","regex_length"),
                (b"could not parse regex","regex_syntax"),
                (b"address already in use","address_in_use"),
                (b"permission denied","permission"),
                (b"unknown directive","unknown_directive"),
                (b"conflicting","config_conflict"),
                (b"certificate","certificate"),
                (b"no such file","missing_file"),
                (b"bind()","bind_failed"))
    reason=next((category for marker,category in categories if marker in detail),"unclassified")
    print("FI_SHARED_ROUTE_CHILD_EXIT="+json.dumps({"service":name,"exit_code":child.returncode,"reason":reason}),flush=True)
    raise ValueError(name+"_canary_exited")

def start_child(name,args,src,children):
    log=src/(name+".startup.log")
    with log.open("xb") as out:
        child=subprocess.Popen(args,stdout=out,stderr=subprocess.STDOUT)
    children.append(child)
    return child,log

def stage(src):
    host(FI);private_dir(STATE);private_dir(src)
    command("systemctl","is-active","--quiet","mnebyvpn-fi-dns-private.service")
    p=json.loads(read(src/"policy.json",500000))
    need(set(p)=={"exact","families","source_sha256"} and re.fullmatch("[a-f0-9]{64}",p["source_sha256"]),"bad_catalog_envelope")
    for key,min_count in (("exact",262),("families",75)):
        rows=p[key]
        need(isinstance(rows,list) and min_count<=len(rows)<=8192 and rows==sorted(set(rows)),"bad_catalog_shape")
        for row in rows:hostname(row)
    need(not covered(p,"example.org") and not covered(p,"mnebyvpn.site"),"unexpected_control_route")
    for port in (18855,14443):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:s.bind(("127.0.0.1",port))
    def public():
        return command("ss","-H","-lnt","sport = :853").strip()
    need(not public(),"public_dns_already_present")
    core=render_core(p,read(STATE/"PrivateCorefile",120000).decode("ascii"))
    nginx=render_nginx(p)
    immutable(src/"Corefile",core.encode())
    immutable(src/"nginx.conf",nginx.encode())
    command("nginx","-t","-c",str(src/"nginx.conf"),"-p",str(src),timeout=15)
    children=[]
    try:
        core_child,core_log=start_child("coredns",[str(COREDNS),"-conf",str(src/"Corefile")],src,children)
        nginx_child,nginx_log=start_child("nginx",["nginx","-c",str(src/"nginx.conf"),"-p",str(src),"-g","daemon off;"],src,children)
        for _ in range(20):
            startup_diagnostic("coredns",core_child,core_log)
            startup_diagnostic("nginx",nginx_child,nginx_log)
            try:
                with socket.create_connection(("127.0.0.1",18855),timeout=.5),socket.create_connection(("127.0.0.1",14443),timeout=.5):pass
                break
            except OSError:time.sleep(.5)
        else:
            startup_diagnostic("coredns",core_child,core_log)
            startup_diagnostic("nginx",nginx_child,nginx_log)
            raise ValueError("route_canary_not_ready")
        print("FI_SHARED_ROUTE_CHILDREN_READY=true",flush=True)
        # These names are test probes, NOT another route source.
        samples=[x for x in ("www.youtube.com","gemini.google.com","api.openai.com","claude.ai","integrate.api.nvidia.com") if covered(p,x)]
        need(len(samples)>=3,"missing_core_service_samples")
        for idx,name in enumerate(samples):
            for kind in (1,28,5,65,64):
                try:dns_query(name,kind)
                except (OSError,ValueError,struct.error) as exc:
                    print("FI_SHARED_ROUTE_DNS_PROBE_FAILED="+str(idx)+":"+str(kind)+":"+type(exc).__name__,flush=True)
                    raise
        print("FI_SHARED_ROUTE_DNS_TYPES_VERIFIED="+str(len(samples)*5),flush=True)
        for idx,name in enumerate(samples):
            try:proxy_probe(name,True)
            except (OSError,ValueError) as exc:
                print("FI_SHARED_ROUTE_TLS_PROBE_FAILED="+str(idx)+":"+type(exc).__name__,flush=True)
                raise
        proxy_probe("example.org",False)
        print("FI_SHARED_ROUTE_TLS_ORIGINS_VERIFIED="+str(len(samples))+";UNKNOWN_SNI_DENIED=true",flush=True)
        need(not public(),"public_dns_changed")
    finally:
        for child in reversed(children):stop(child)
    # Publish staged immutable bundle only after successful real probes.
    private_dir(DEST,True)
    for name in ("policy.json","Corefile","nginx.conf"):
        immutable(DEST/name,read(src/name,500000))
    manifest={"source_sha256":p["source_sha256"],"exact_count":len(p["exact"]),"family_count":len(p["families"]),
        "config_sha256":{name:hashlib.sha256(read(DEST/name,500000)).hexdigest() for name in ("policy.json","Corefile","nginx.conf")},
        "local_canary_verified":True,"public_activation":False}
    immutable(DEST/"manifest.json",(json.dumps(manifest,sort_keys=True)+"\n").encode())
    print("FI_SHARED_ROUTE_STAGED=true;EXACT="+str(len(p["exact"]))+";FAMILIES="+str(len(p["families"]))+";PUBLIC_DNS=false",flush=True)

if __name__=="__main__":
    try:
        os.umask(0o077)
        def interrupted(signum,frame):raise SystemExit(128+signum)
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGHUP,interrupted)
        need(len(sys.argv)==2 and re.fullmatch(r"/run/fi-shared-routes-[0-9]+-[0-9]+",sys.argv[1]),"invalid_stage")
        stage(Path(sys.argv[1]))
    except (OSError,ValueError,RuntimeError,TypeError,IndexError,struct.error,subprocess.SubprocessError) as exc:
        label=str(exc) if type(exc) in (ValueError,RuntimeError) and re.fullmatch("[a-z0-9_]+",str(exc)) else type(exc).__name__
        print("FI_SHARED_ROUTE_BLOCKED="+label,file=sys.stderr,flush=True)
        raise SystemExit(2)
