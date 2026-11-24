#!/usr/bin/env python3
"""Install private FI data plane, verify real TLS origin and denied ingress."""
from __future__ import annotations
import asyncio
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time
import uuid

from fi_dns_ssh_stage import FI,FI_ROOT,FI_RUNTIME,CONTROLLER_PIN,host,private_dir,read,immutable,command,require

UNIT="mnebyvpn-fi-dns-private.service"
UNIT_PATH=Path("/etc/systemd/system")/UNIT
STATE=FI_ROOT/"dns-auth"
MODULES=("fi_dns_private_runtime.py","fi_dns_ssh_stage.py","fi_dns_origin_canary.py",
         "fi_regional_cert_stage.py","fi_dns_guarded_ingress.py","fi_dns_highwater.py",
         "fi_dns_signed_grants.py","fi_dns_meter_rpc.py","fi_enrollment_ssh.py",
         "fi_dns_reverse_channel.py","fi_dns_ssh_bridge.py","fi_dns_metered_dot.py",
         "fi_dns_tls_session.py")

def no_public_dns():
    require(not command("ss","-H","-lnt","sport = :853").strip(),"public_tcp_853_present")
    require(not command("ss","-H","-lnu","sport = :853").strip(),"public_udp_853_present")

def install(src):
    host(FI);private_dir(FI_ROOT);private_dir(FI_RUNTIME);no_public_dns()
    require(subprocess.run(["systemctl","is-active","--quiet",UNIT],timeout=5).returncode!=0,"private_unit_already_active")
    for port in (8853,18854):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:s.bind(("127.0.0.1",port))
    for base in (UNIT_PATH.parent,Path("/run/systemd/system"),Path("/usr/lib/systemd/system"),Path("/lib/systemd/system")):
        drop=base/(UNIT+".d")
        require(not drop.exists() and not drop.is_symlink(),"private_unit_override")
        if base!=UNIT_PATH.parent:
            require(not (base/UNIT).exists() and not (base/UNIT).is_symlink(),"foreign_private_unit")
    for name in MODULES:immutable(FI_RUNTIME/name,read(src/name,200000))
    sys.path.insert(0,str(FI_RUNTIME))
    from fi_dns_private_runtime import corefile_bytes,prepare,CONFIG,MARKER,REGIONAL_TLS,verify_pair
    private_dir(STATE,True)
    verify_pair(REGIONAL_TLS)
    immutable(CONFIG,corefile_bytes(prepare().read_bytes()))
    immutable(UNIT_PATH,read(src/UNIT,10000))
    command("systemd-analyze","verify",str(UNIT_PATH))
    command("systemctl","daemon-reload")
    immutable(MARKER,b"fi-dns-private-v1\n")
    immutable(src/"started",b"fi-dns-private-v1\n")
    command("systemctl","start",UNIT)
    print("FI_PRIVATE_UNIT_STARTED=true",flush=True)

async def probe():
    host(FI);sys.path.insert(0,str(FI_RUNTIME))
    from fi_dns_origin_canary import HOSTS,EXTERNAL_QUERY,dot_probe,query_bytes
    from fi_dns_guarded_ingress import SNAPSHOT,CONTROLLER
    from fi_dns_signed_grants import load
    from fi_dns_reverse_channel import ReverseTransport
    from fi_dns_meter_rpc import protected_openssl_meter
    ctx=ssl.create_default_context()
    for _ in range(45):
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection("127.0.0.1",18854,
               ssl=ctx,server_hostname=HOSTS[0]),timeout=3)
            break
        except (OSError,ValueError,asyncio.TimeoutError):await asyncio.sleep(1)
    else:raise RuntimeError("metered_tls_not_ready")
    try:
        q=query_bytes(0x4a71,EXTERNAL_QUERY)
        writer.write(struct.pack("!H",len(q))+q)
        await writer.drain()
        require(await asyncio.wait_for(reader.read(2),5)==b"","unentitled_query_not_denied")
    finally:
        writer.close()
        try:await asyncio.wait_for(writer.wait_closed(),2)
        except (OSError,asyncio.TimeoutError):pass
    print("FI_PRIVATE_TLS_UNENTITLED_DENIED=true",flush=True)
    require(await asyncio.to_thread(dot_probe,HOSTS[1],EXTERNAL_QUERY),"origin_probe_failed")
    print("FI_PRIVATE_REAL_ORIGIN_DOT_A_VERIFIED=true",flush=True)
    policy=load(SNAPSHOT,CONTROLLER,CONTROLLER_PIN)
    require(policy["grants"]==[],"unexpected_grants")
    old=policy["revision"]
    # Prove actual continuous signed receiver refresh, not just boot snapshot.
    for _ in range(45):
        await asyncio.sleep(1)
        policy=load(SNAPSHOT,CONTROLLER,CONTROLLER_PIN)
        require(policy["grants"]==[],"unexpected_grants")
        if policy["revision"]>old:break
    else:raise RuntimeError("snapshot_not_refreshed")
    print("FI_PRIVATE_SIGNED_SNAPSHOT_REFRESHED=true",flush=True)
    meter=protected_openssl_meter(ReverseTransport(),FI_ROOT/"identity/node-private.pk8",CONTROLLER,CONTROLLER_PIN)
    require(await meter._apply("reserve",uuid.uuid4(),secrets.token_hex(32))=="DENY_DISABLED","meter_gate_not_closed")
    print("FI_PRIVATE_SIGNED_METER_DENIAL=true",flush=True)
    command("systemctl","is-active","--quiet",UNIT)
    for port in (8853,18854):
        lines=command("ss","-H","-lnt","sport = :"+str(port)).decode().splitlines()
        require(len(lines)==1 and lines[0].split()[3]=="127.0.0.1:"+str(port),"listener_not_loopback")
    no_public_dns()
    print("FI_PRIVATE_DATAPLANE_VERIFIED=true;PUBLIC_DNS=false;CUSTOMER_GRANTS=0;ROUTES=0",flush=True)

if __name__=="__main__":
    try:
        os.umask(0o077)
        if sys.argv[1:]==["probe"]:asyncio.run(probe())
        else:
            require(len(sys.argv)==3 and re.fullmatch(r"/run/fi-dns-private-[0-9]+-[0-9]+",sys.argv[2]),"invalid_stage")
            src=Path(sys.argv[2]);private_dir(src)
            if sys.argv[1]=="install":install(src)
            elif sys.argv[1]=="rollback":
                host(FI)
                if (src/"started").exists():
                    require(read(src/"started",100)==b"fi-dns-private-v1\n","rollback_marker_mismatch")
                    command("systemctl","stop",UNIT)
                    (STATE/"private-dataplane.enable").unlink(missing_ok=True)
                    print("FI_PRIVATE_UNIT_ROLLED_BACK=true")
            else:raise RuntimeError("invalid_action")
    except (OSError,ValueError,TypeError,RuntimeError,subprocess.SubprocessError,asyncio.IncompleteReadError) as e:
        label=str(e) if type(e) is RuntimeError and re.fullmatch(r"[a-z0-9_]+",str(e)) else type(e).__name__
        print("FI_PRIVATE_STAGE_BLOCKED="+label,file=sys.stderr,flush=True)
        raise SystemExit(2)
