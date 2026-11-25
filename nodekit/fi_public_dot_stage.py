#!/usr/bin/env python3
"""Expose only metered TLS backend; pilot gate remains OFF."""
import asyncio
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys

from fi_dns_ssh_stage import FI,FI_ROOT,FI_RUNTIME,CONTROLLER_PIN,host,private_dir,read,immutable,command,require
from fi_country_transaction import NEW as COUNTRY_DNS, OLD as LEGACY_DNS
from fi_country_stage import MARKER as COUNTRY_MARKER, STAMP as COUNTRY_STAMP
from fi_country_stage import active, ctl, enabled, listeners, meter_closed, verify_old_sni_denial
from fi_dns_guarded_ingress import SNAPSHOT,CONTROLLER
from fi_dns_signed_grants import load
from fi_dns_origin_canary import HOSTS,EXTERNAL_QUERY,query_bytes
from fi_sni_egress_guard import verify,uid,FINGERPRINT
from fi_regional_cert_stage import verify_pair,DEST as CERT

STATE=FI_ROOT/"dns-auth"
MARKER=STATE/"public-dot.enable"
SOCKET="mnebyvpn-fi-public-dot.socket"
SERVICE="mnebyvpn-fi-public-dot.service"
UNITS=(COUNTRY_DNS,"mnebyvpn-fi-sni-routed-v3.service","mnebyvpn-fi-sni-egress-guard.service")
UNIT_DIR=Path("/etc/systemd/system")

def no_override(unit):
    for base in (UNIT_DIR, Path("/run/systemd/system"), Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")):
        drop_in = base / (unit + ".d")
        require(not drop_in.exists() and not drop_in.is_symlink(), "unit_override")
        if base != UNIT_DIR:
            path = base / unit
            require(not path.exists() and not path.is_symlink(), "foreign_unit")

def guard():
    n=uid();parts=read(FINGERPRINT,100).decode().strip().split(":")
    require(len(parts)==2 and parts[0]==str(n),"guard_uid_mismatch")
    verify(n,parts[1])
    require(all(active(u) for u in UNITS),"required_service_inactive")
    require(enabled(COUNTRY_DNS) and not active(LEGACY_DNS) and not enabled(LEGACY_DNS),"country_runtime_not_committed")
    require(FI_RUNTIME == Path("/opt/mnebyvpn-fi-dns-country-v2"),"wrong_country_runtime")
    require(read(COUNTRY_MARKER,100) == COUNTRY_STAMP,"country_runtime_marker_missing")
    require(load(SNAPSHOT,CONTROLLER,CONTROLLER_PIN)["grants"]==[],"unexpected_grants")
    require(listeners(8853)==["127.0.0.1:8853"] and listeners(18854)==["127.0.0.1:18854"] and listeners(14443)==["127.0.0.1:14443"],"private_listener_drift")
    require(not listeners(853, udp=True),"udp_853_conflict")
    verify_pair(CERT)

def deny_query(address,hostname):
    with socket.create_connection((address,853),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=hostname) as tls:
            q=query_bytes(0x4a71,EXTERNAL_QUERY)
            tls.sendall(struct.pack("!H",len(q))+q)
            require(tls.recv(2)==b"","unentitled_query_not_denied")

def rollback(src):
    host(FI)
    if not (src/"public-started").exists():return
    require(read(src/"public-started",100)==b"fi-public-dot-v1\n","bad_rollback_marker")
    ctl("disable","--now",SOCKET)
    ctl("stop",SERVICE)
    MARKER.unlink(missing_ok=True)
    require(not listeners(853),"public_rollback_listener_present")
    require(all(active(u) for u in UNITS),"private_service_changed")
    (src/"public-started").unlink()
    print("FI_PUBLIC_DOT_ROLLBACK_VERIFIED=true",flush=True)

def stage(src):
    host(FI);private_dir(STATE);guard()
    require(not active(SOCKET) and not active(SERVICE) and not listeners(853),"public_853_already_present")
    require(not MARKER.exists() and not MARKER.is_symlink(),"public_marker_present")
    asyncio.run(meter_closed())
    verify_old_sni_denial()
    immutable(STATE/"PublicDotRelay.py",read(src/"fi_public_dot_relay.py",200000))
    for unit in (SOCKET,SERVICE):
        no_override(unit)
        immutable(UNIT_DIR/unit,read(src/unit,10000))
    command("systemd-analyze","verify",str(UNIT_DIR/SOCKET),str(UNIT_DIR/SERVICE),timeout=20)
    ctl("daemon-reload")
    immutable(src/"public-started",b"fi-public-dot-v1\n")
    try:
        immutable(MARKER,b"fi-public-dot-v1\n")
        ctl("start",SOCKET)
        require(listeners(853)==[FI+":853"],"unexpected_public_listener")
        for name in HOSTS:deny_query(FI,name)
        guard()
        pid=int(ctl("show",SERVICE,"-p","MainPID","--value").strip())
        require(pid>1,"relay_pid_missing")
        status=dict(l.split(":",1) for l in (Path("/proc")/str(pid)/"status").read_text().splitlines() if ":" in l)
        require(all(int(x)>0 for x in status["Uid"].split()) and int(status["CapEff"].strip(),16)==0,"relay_privilege_drift")
        print("FI_PUBLIC_DOT_LOCAL_TLS_DENIED=true;UNPRIVILEGED_RELAY=true",flush=True)
    except BaseException:
        rollback(src);raise

def commit(src):
    host(FI);guard()
    asyncio.run(meter_closed())
    require(read(src/"public-started",100)==b"fi-public-dot-v1\n","public_stage_missing")
    require(read(MARKER,100)==b"fi-public-dot-v1\n","public_marker_missing")
    require(active(SOCKET) and active(SERVICE) and listeners(853)==[FI+":853"],"public_relay_not_ready")
    ctl("enable",SOCKET)
    require(ctl("is-enabled",SOCKET).strip()==b"enabled","public_enable_failed")
    print("FI_PUBLIC_DOT_LISTENER_VERIFIED=true;TCP_853=true;GRANTS=0;METER_GATE=OFF;PUBLIC_HTTPS_UNCHANGED=true",flush=True)

if __name__=="__main__":
    try:
        os.umask(0o077)
        def interrupted(signum,frame):raise SystemExit(128+signum)
        signal.signal(signal.SIGTERM,interrupted)
        signal.signal(signal.SIGHUP,interrupted)
        require(len(sys.argv)==3 and re.fullmatch(r"/run/fi-public-dot-[0-9]+-[0-9]+",sys.argv[2]),"invalid_stage")
        src=Path(sys.argv[2]);private_dir(src)
        action={"stage":stage,"rollback":rollback,"commit":commit}.get(sys.argv[1])
        require(action is not None,"invalid_action")
        action(src)
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.SubprocessError,asyncio.IncompleteReadError) as e:
        label=str(e) if re.fullmatch(r"[a-z0-9_]+",str(e)) else type(e).__name__
        print("FI_PUBLIC_DOT_BLOCKED="+label,file=sys.stderr,flush=True)
        raise SystemExit(2)
