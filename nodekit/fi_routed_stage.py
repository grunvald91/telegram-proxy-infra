#!/usr/bin/env python3
"""Switch the verified FI route bundle into permanent private DNS and SNI services.
No public 853/443, grant, billing, firewall, RU or DE changes.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time

from fi_dns_ssh_stage import FI,FI_ROOT,FI_RUNTIME,CONTROLLER_PIN,host,private_dir,read,immutable,command,require
from fi_shared_routes import render_core,render_nginx,covered,hostname
from fi_shared_routes_stage import proxy_probe
from fi_dns_private_runtime import corefile_bytes,prepare
from fi_dns_origin_canary import HOSTS,EXTERNAL_QUERY,dot_probe,query_bytes
from fi_dns_guarded_ingress import SNAPSHOT,CONTROLLER
from fi_dns_signed_grants import load

STATE=FI_ROOT/"dns-auth"
BUNDLE=STATE/"shared-routes"
MARKER=STATE/"routed-dataplane.enable"
OLD="mnebyvpn-fi-dns-private.service"
DNS="mnebyvpn-fi-dns-routed.service"
PROXY="mnebyvpn-fi-sni-routed.service"
UNIT_DIR=Path("/etc/systemd/system")

def ctl(*args):
    return command("systemctl",*args,timeout=30)

def active(unit):
    return subprocess.run(["systemctl","is-active","--quiet",unit],capture_output=True,timeout=8).returncode==0

def listeners(port):
    return [line.split()[3] for line in command("ss","-H","-lnt","sport = :"+str(port)).decode().splitlines()]

def check_public():
    require(not listeners(853),"public_853_conflict")
    require(not command("ss","-H","-lnu","sport = :853").strip(),"public_udp_853_conflict")

def validated_bundle():
    private_dir(BUNDLE)
    r=json.loads(read(BUNDLE/"manifest.json",10000))
    require(r["local_canary_verified"] is True and r["public_activation"] is False,"unverified_bundle")
    for name in ("policy.json","Corefile","nginx.conf"):
        require(hashlib.sha256(read(BUNDLE/name,500000)).hexdigest()==r["config_sha256"][name],"route_hash_mismatch")
    p=json.loads(read(BUNDLE/"policy.json",500000))
    require(p["source_sha256"]==r["source_sha256"],"source_hash_mismatch")
    require(len(p["exact"])==r["exact_count"] and len(p["families"])==r["family_count"],"count_mismatch")
    for name in p["exact"]+p["families"]:hostname(name)
    require(not covered(p,"example.org"),"control_route_overlap")
    base=read(STATE/"PrivateCorefile",120000)
    require(base==corefile_bytes(prepare().read_bytes()),"original_config_drift")
    core=render_core(p,base.decode())
    nginx=render_nginx(p)
    require(core.encode()==read(BUNDLE/"Corefile",500000) and nginx.encode()==read(BUNDLE/"nginx.conf",500000),"renderer_drift")
    return p,core.replace("tls://.:18855 {","tls://.:8853 {").encode(),nginx.replace("/run/mnebyvpn-fi-route-canary.pid","/run/mnebyvpn-fi-route/nginx.pid").encode()

def no_override(unit):
    for base in (UNIT_DIR,Path("/run/systemd/system"),Path("/usr/lib/systemd/system"),Path("/lib/systemd/system")):
        drop=base/(unit+".d")
        require(not drop.exists() and not drop.is_symlink(),"unit_override")
        if base!=UNIT_DIR:
            path=base/unit
            require(not path.exists() and not path.is_symlink(),"foreign_unit")

def denied():
    with socket.create_connection(("127.0.0.1",18854),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=HOSTS[0]) as tls:
            q=query_bytes(0x4a71,EXTERNAL_QUERY)
            tls.sendall(struct.pack("!H",len(q))+q)
            require(tls.recv(2)==b"","unknown_personal_token_accepted")

def probe(p):
    for _ in range(30):
        if active(DNS) and active(PROXY) and listeners(8853)==["127.0.0.1:8853"] and listeners(18854)==["127.0.0.1:18854"] and listeners(14443)==["127.0.0.1:14443"]:break
        time.sleep(1)
    else:raise RuntimeError("routed_services_not_ready")
    require(dot_probe(HOSTS[0],EXTERNAL_QUERY),"ordinary_dns_failed")
    # The staged probe uses fixed loopback port 18855. Reuse its DNS protocol
    # and strict verification with a port argument, never an external origin.
    from fi_routed_probe import routed_dns_query
    names=[x for x in ("www.youtube.com","gemini.google.com","api.openai.com","claude.ai","integrate.api.nvidia.com") if covered(p,x)]
    require(len(names)>=3,"sample_missing")
    for name in names:
        for kind in (1,28,5,64,65):routed_dns_query(name,kind,port=8853)
        proxy_probe(name,True)
    proxy_probe("example.org",False)
    denied()
    policy=load(SNAPSHOT,CONTROLLER,CONTROLLER_PIN)
    require(policy["grants"]==[],"unexpected_grants")
    check_public()
    require(not active(OLD),"legacy_still_active")
    print("FI_ROUTED_LOCAL_DNS_AND_SNI_VERIFIED="+str(len(names))+";UNKNOWN_DENIED=true",flush=True)

def rollback(src):
    host(FI)
    if not (src/"switch-started").exists():return
    require(read(src/"switch-started",100)==b"fi-routed-v2\n","rollback_marker_mismatch")
    for unit in (DNS,PROXY):
        ctl("disable","--now",unit)
    MARKER.unlink(missing_ok=True)
    ctl("start",OLD)
    for _ in range(25):
        if active(OLD) and listeners(18854)==["127.0.0.1:18854"]:break
        time.sleep(1)
    else:raise RuntimeError("legacy_restore_failed")
    denied();check_public()
    (src/"switch-started").unlink(missing_ok=True)
    print("FI_ROUTED_ROLLBACK_VERIFIED=true",flush=True)

def stage(src):
    host(FI);private_dir(STATE);private_dir(FI_RUNTIME);check_public()
    require(active(OLD) and not active(DNS) and not active(PROXY),"unexpected_current_services")
    require(not MARKER.exists() and not MARKER.is_symlink(),"routed_marker_present")
    require(load(SNAPSHOT,CONTROLLER,CONTROLLER_PIN)["grants"]==[],"gate_not_empty")
    p,core,nginx=validated_bundle()
    for name in ("fi_routed_runtime.py","fi_shared_routes.py","fi_shared_routes_stage.py","fi_routed_probe.py"):
        immutable(FI_RUNTIME/name,read(src/name,200000))
    immutable(STATE/"RoutedCorefile",core)
    immutable(STATE/"RoutedNginx.conf",nginx)
    for unit in (OLD,DNS,PROXY):no_override(unit)
    for unit in (DNS,PROXY):
        immutable(UNIT_DIR/unit,read(src/unit,10000))
    # Nginx validates the exact permanent configuration before cutover.
    nginx_dir=Path("/run/mnebyvpn-fi-route")
    private_dir(nginx_dir,True)
    command("nginx","-t","-c",str(STATE/"RoutedNginx.conf"),"-p",str(nginx_dir),timeout=15)
    command("systemd-analyze","verify",str(UNIT_DIR/DNS),str(UNIT_DIR/PROXY),timeout=20)
    ctl("daemon-reload")
    immutable(src/"switch-started",b"fi-routed-v2\n")
    try:
        immutable(MARKER,b"fi-dns-routed-v2\n")
        ctl("stop",OLD)
        ctl("start",DNS,PROXY)
        probe(p)
        ctl("enable",DNS,PROXY)
        require(ctl("is-enabled",DNS).strip()==b"enabled" and ctl("is-enabled",PROXY).strip()==b"enabled","enable_failed")
        require(active(DNS) and active(PROXY),"service_stopped_after_enable")
    except BaseException:
        rollback(src)
        raise
    print("FI_ROUTED_PERMANENT_VERIFIED=true;EXACT="+str(len(p["exact"]))+";FAMILIES="+str(len(p["families"]))+";PUBLIC_DNS=false;GRANTS=0",flush=True)

if __name__=="__main__":
    try:
        os.umask(0o077)
        def interrupted(signum,frame):raise SystemExit(128+signum)
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGHUP,interrupted)
        require(len(sys.argv)==3 and re.fullmatch(r"/run/fi-routed-[0-9]+-[0-9]+",sys.argv[2]),"invalid_stage")
        src=Path(sys.argv[2]);private_dir(src)
        if sys.argv[1]=="stage":stage(src)
        elif sys.argv[1]=="rollback":rollback(src)
        else:raise RuntimeError("invalid_action")
    except (OSError,ValueError,RuntimeError,TypeError,KeyError,subprocess.SubprocessError) as e:
        label=str(e) if type(e) is RuntimeError and re.fullmatch(r"[a-z0-9_]+",str(e)) else type(e).__name__
        print("FI_ROUTED_STAGE_BLOCKED="+label,file=sys.stderr,flush=True)
        raise SystemExit(2)
