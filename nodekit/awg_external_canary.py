#!/usr/bin/env python3
"""Temporary external AWG 3.1 test on FI. Never a customer access endpoint.

Only one freshly generated test peer and the SSH origin public IP are allowed.
The temporary NAT/INPUT/FORWARD entries are comment-scoped to this canary.
Independent systemd timer and finally cleanup provide two shutdown paths.
"""
from __future__ import annotations
import argparse
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

from awg_lifecycle import AWG_BIN, active_unit, enabled_unit, unit_name, validate
from install_components import node_ready, safe_manifest

NODE="fi-test-01"
HOST="fi.mnebyvpn.site"
ROOT=Path("/var/lib/mnebyvpn-nodekit")
STATE=Path("/run/nodekit-fi-awg-external.json")
LOCK=Path("/run/nodekit-fi-awg-external.lock")
PERSISTENT=Path("/opt/mnebyvpn-nodekit/awg_external_canary.py")
PORT=51821
CLIENT="10.73.91.2"
MARK="nodekit-fi-awg-canary"
KEY=re.compile(r"[A-Za-z0-9+/]{43}=\Z")
TIMER="nodekit-fi-awg-canary-expiry"
class CanaryError(ValueError):pass

def call(parts,check=True,timeout=12):
    return subprocess.run(parts,check=check,capture_output=True,text=True,timeout=timeout)

def key_ok(value):
    if not isinstance(value,str) or not KEY.fullmatch(value):return False
    raw=base64.b64decode(value,validate=True)
    return len(raw)==32 and base64.b64encode(raw).decode()==value

def source_ip(value):
    ip=ipaddress.IPv4Address(value)
    if str(ip)!=value or not ip.is_global:raise CanaryError("Invalid SSH runner IPv4")
    return value

def firewall(source):
    source_ip(source)
    note=["-m","comment","--comment",MARK]
    return [
       ("filter","INPUT",["-p","udp","-s",source,"--dport","51821",*note,"-j","ACCEPT"]),
       ("filter","FORWARD",["-i","awg0","-o","eth0","-s",CLIENT+"/32",*note,"-j","ACCEPT"]),
       ("filter","FORWARD",["-i","eth0","-o","awg0","-d",CLIENT+"/32",
                          "-m","conntrack","--ctstate","ESTABLISHED,RELATED",*note,"-j","ACCEPT"]),
       ("nat","POSTROUTING",["-s",CLIENT+"/32","-o","eth0",*note,"-j","MASQUERADE"]),
    ]

def rule(table,op,chain,args,check=True):
    return call(["iptables","-w","4","-t",table,op,chain,*args],check=check)

def lock():
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    st=os.fstat(fd)
    if st.st_uid!=0 or not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        os.close(fd);raise CanaryError("Insecure lock")
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd

def unlock(fd):
    fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def read_state():
    if STATE.is_symlink():raise CanaryError("Unsafe canary state")
    if not STATE.exists():return None
    st=STATE.stat()
    if st.st_uid!=0 or st.st_mode & 0o077 or st.st_size>1024:
        raise CanaryError("Unsafe state permissions")
    value=json.loads(STATE.read_text())
    if set(value)!={"source","forward","expiry"} or value["forward"] not in ("0","1"):
        raise CanaryError("Corrupt canary state")
    source_ip(value["source"])
    return value

def check_node():
    node=node_ready(ROOT,NODE)
    validate(node)
    manifest=safe_manifest(node/"manifest.json")
    if (manifest.get("advertise_host")!=HOST or
       manifest.get("activation_enabled") is not False or
       manifest.get("registration_enabled") is not False):
        raise CanaryError("Node no longer isolated")
    if (active_unit(unit_name(NODE)) or enabled_unit(unit_name(NODE)) or
        active_unit("mnebyvpn-nodekit-awg-watchdog@"+NODE+".service") or
        enabled_unit("mnebyvpn-nodekit-awg-watchdog@"+NODE+".service")):
        raise CanaryError("AWG in use")
    route=json.loads(call(["ip","-j","route","get","1.1.1.1"]).stdout)
    if not route or route[0].get("dev")!="eth0":raise CanaryError("Egress interface changed")
    return node

def material():
    node=check_node()
    policy=safe_manifest(node/"amneziawg"/"manifest.json")
    config=(node/"amneziawg"/"awg0.conf").read_text()
    header=re.search(r"(?m)^HeaderProtectionKey = ([A-Za-z0-9+/]{43}=)$",config)
    pub=policy.get("server_public_key")
    if not header or not key_ok(header.group(1)) or not key_ok(pub):
        raise CanaryError("Missing AWG3.1 headers")
    return {"server_public_key":pub,"header_key":header.group(1),
            "hostname":HOST,"port":PORT,"client_ip":CLIENT}

def cleanup():
    fd=lock()
    try:
        state=read_state()
        if state is None:return
        call(["systemctl","stop",unit_name(NODE)],check=False,timeout=30)
        for table,chain,args in reversed(firewall(state["source"])):
            rule(table,"-D",chain,args,check=False)
        if state["forward"]=="0":
            call(["sysctl","-w","net.ipv4.ip_forward=0"],check=False)
        STATE.unlink(missing_ok=True)
        # The independent cleanup timer is no longer necessary after
        # a successful explicit cleanup. Its service cannot restart AWG.
        call(["systemctl","stop",TIMER+".timer"],check=False,timeout=10)
    finally:unlock(fd)

def prepare(peer,source,seconds):
    if not key_ok(peer) or not 30<=seconds<=90:raise CanaryError("Invalid peer or TTL")
    source_ip(source)
    ssh=os.environ.get("SSH_CONNECTION","").split()
    if not ssh or ssh[0]!=source:raise CanaryError("Peer origin does not match SSH origin")
    check_node()
    if call(["ss","-H","-lun","sport","=",":51821"]).stdout.strip():
        raise CanaryError("UDP port in use")
    for table,chain,args in firewall(source):
        if MARK in rule(table,"-S",chain,[]).stdout:
            raise CanaryError("Old firewall entries require operator review")
    if PERSISTENT.is_symlink() or not PERSISTENT.is_file() or PERSISTENT.read_bytes()!=Path(__file__).read_bytes():
        raise CanaryError("Missing approved cleanup code")
    fd=lock()
    try:
        if read_state() is not None:raise CanaryError("Already running")
        forward=Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        if forward not in ("0","1"):raise CanaryError("Invalid forwarding mode")
        if call(["systemctl","is-active","--quiet",TIMER+".timer"],check=False).returncode==0:
            raise CanaryError("Previous failsafe cleanup timer still active")
        # Service is started only after a separate on-VPS cleanup is scheduled.
        call(["systemd-run","--unit="+TIMER,"--on-active="+str(seconds+30)+"s",
              "/usr/bin/python3",str(PERSISTENT),"--mode","cleanup"])
        descriptor=os.open(STATE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,"w") as out:
            json.dump({"source":source,"forward":forward,
                       "expiry":time.time()+seconds+30},out)
    finally:unlock(fd)
    try:
        print("AWG_EXTERNAL_STEP=TEMPORARY_FIREWALL",flush=True)
        for table,chain,args in firewall(source):
            rule(table,"-I",chain,["1",*args])
        call(["sysctl","-w","net.ipv4.ip_forward=1"])
        print("AWG_EXTERNAL_STEP=AWG_SERVER",flush=True)
        call(["systemctl","start",unit_name(NODE)],timeout=40)
        call([str(AWG_BIN/"awg"),"set","awg0","peer",peer,
              "allowed-ips",CLIENT+"/32"])
        print("AWG_EXTERNAL_READY=TRUE",flush=True)
        until=time.monotonic()+seconds
        while time.monotonic()<until and STATE.exists():
            time.sleep(1)
    finally:
        print("AWG_EXTERNAL_STEP=REMOVING_TEST_RULES",flush=True)
        cleanup()

def install():
    check_node()
    if PERSISTENT.parent.is_symlink() or not PERSISTENT.parent.is_dir():
        raise CanaryError("Missing root-owned Nodekit code directory")
    code=Path(__file__).read_bytes()
    if PERSISTENT.exists() or PERSISTENT.is_symlink():
        if PERSISTENT.is_symlink() or PERSISTENT.stat().st_uid!=0 or PERSISTENT.read_bytes()!=code:
            raise CanaryError("Existing cleanup script differs")
    else:
        fd=os.open(PERSISTENT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as out:out.write(code)
    return {"installed":True,"activated":False,"published":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",required=True,choices=("install","material","run","cleanup","status"))
    p.add_argument("--peer-public")
    p.add_argument("--source-ip")
    p.add_argument("--seconds",type=int,default=60)
    args=p.parse_args()
    try:
        if os.geteuid()!=0:raise CanaryError("Root required")
        if args.mode=="cleanup":
            cleanup()
            print("AWG_EXTERNAL_CLEANUP=TRUE")
        elif args.mode=="install":print(json.dumps(install(),sort_keys=True))
        elif args.mode=="material":print(json.dumps(material(),sort_keys=True))
        elif args.mode=="status":
            state=read_state()
            print(json.dumps({"ready":bool(state) and active_unit(unit_name(NODE)),
                              "expires_in":max(0,int(state["expiry"]-time.time())) if state else 0}))
        elif args.mode=="run":
            def interrupted(_signal,_frame):raise CanaryError("External canary interrupted")
            signal.signal(signal.SIGTERM,interrupted)
            signal.signal(signal.SIGINT,interrupted)
            prepare(args.peer_public,args.source_ip,args.seconds)
        return 0
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        print("AWG_EXTERNAL_ERROR="+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
