#!/usr/bin/env python3
"""Guarded DE89 MNEBYDNS configuration deployment and reboot-safe rollback.

Install alongside mnebydns_nov8_restore_safety.py under /opt/mnebydns-maintenance.
Only explicit, hash-pinned manifests can modify three allowlisted configs.
The normal 'status' command is read-only. No network or subscriber data is logged.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
import base64
import hashlib
import grp
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

from mnebydns_dns_policy_guard import preserved, smoke_check
from mnebydns_nov8_restore_safety import (
    FileState, atomic_replace, capture, commit_marker, conditional_rollback,
    digest, persistent_watchdog, route_lock,
)

INSTALL=Path("/opt/mnebydns-maintenance")
TXROOT=Path("/var/lib/mnebydns-safe-deploy")
STAGE=INSTALL/"stage"
LIVE={
    "dns":Path("/opt/mnebydns-dot/Corefile"),
    "shared":Path("/etc/nginx/nginx.conf"),
    "pilot":Path("/etc/mnebydns-googlepilot/nginx.conf"),
}
SERVICE={"dns":"mnebydns-dot.service","shared":"nginx.service",
         "pilot":"mnebydns-googlepilot.service"}
PORT={"dns":853,"shared":443,"pilot":15449}
NAME=re.compile(r"^[a-z0-9][a-z0-9-]{5,32}$")
SHA=re.compile(r"^[0-9a-f]{64}$")
UNITPREFIX="mnebydns-safe-recover-"
OWNERROOT=Path("/opt/mnebydns-owner-domain")

def cmd(*argv,timeout=25):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout)
    if p.returncode:
        # Avoid accidental release of cert paths, content or customer data.
        raise RuntimeError("Command failed: "+Path(argv[0]).name+
                           " exit="+str(p.returncode))
    return p.stdout.strip()

def fsync_dir(path:Path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def write_durable(path:Path,data:bytes,mode=0o600):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
    fd=os.open(path,flags,mode)
    try:
        offset=0
        while offset<len(data):
            n=os.write(fd,data[offset:])
            if n<=0:raise OSError("Short write")
            offset+=n
        os.fsync(fd)
    finally:os.close(fd)
    fsync_dir(path.parent)

def regular_read(path:Path,maxsize=600000):
    state=capture(path)
    size=path.stat().st_size
    if not 0<size<=maxsize:raise ValueError("Config size outside expected bounds")
    data=path.read_bytes()
    if digest(data)!=state.sha256:raise RuntimeError("Concurrent config update")
    return state,data

def state_obj(s:FileState):
    return {"sha256":s.sha256,"uid":s.uid,"gid":s.gid,"mode":s.mode,
            "xattrs":[[k,base64.b64encode(v).decode("ascii")] for k,v in s.xattrs]}

def state_from(j):
    if not SHA.fullmatch(j["sha256"]):raise ValueError("Invalid recorded hash")
    return FileState(j["sha256"],int(j["uid"]),int(j["gid"]),int(j["mode"]),
                     tuple((k,base64.b64decode(v,validate=True)) for k,v in j["xattrs"]))

def services_ok(names):
    status={}
    for key in sorted(names):
        service=SERVICE[key]
        p=subprocess.run(["systemctl","is-active","--quiet",service],
                         capture_output=True,timeout=8)
        port=PORT[key]
        listen=subprocess.run(["ss","-H","-lnt",f"sport = :{port}"],
                              capture_output=True,text=True,timeout=8)
        status[key]={"service_active":p.returncode==0,
                     "tcp_listener":listen.returncode==0 and bool(listen.stdout.strip())}
    return status

def require_services_healthy(names):
    states=services_ok(names)
    for key,health in states.items():
        if not all(health.values()):
            raise RuntimeError("Service or listener not active: "+key)
    return states

def verify_system():
    if os.geteuid()!=0:raise PermissionError("Root privileges required")
    if not INSTALL.is_dir() or not TXROOT.is_dir():
        raise RuntimeError("Installer directories not initialized")
    if INSTALL.is_symlink() or TXROOT.is_symlink() or STAGE.is_symlink():
        raise RuntimeError("Untrusted installer location")

def ensure_dns_reader_access():
    """CoreDNS DynamicUser must retain read-only access to the config."""
    s=capture(LIVE["dns"])
    if s.uid!=0 or s.gid!=grp.getgrnam("mnebydns-corefile-readers").gr_gid or s.mode!=0o640:
        raise RuntimeError("CoreDNS Corefile must be root:reader mode 0640")
    raw=cmd("systemctl","show",SERVICE["dns"],"-p","User,DynamicUser,SupplementaryGroups")
    props=dict(line.split("=",1) for line in raw.splitlines() if "=" in line)
    if (props.get("User")!="mnebydns-dot" or
        props.get("DynamicUser")!="yes" or
        "mnebydns-corefile-readers" not in props.get("SupplementaryGroups","").split()):
        raise RuntimeError("CoreDNS service lost restricted reader group")


def manifest_for(name):
    if not NAME.fullmatch(name):raise ValueError("Invalid deployment identifier")
    directory=STAGE/name
    if not directory.is_dir() or directory.is_symlink() or directory.resolve().parent!=STAGE.resolve():
        raise ValueError("Untrusted staged deployment directory")
    ds=directory.stat()
    if ds.st_uid!=0 or stat.S_IMODE(ds.st_mode)!=0o700:
        raise ValueError("Stage must be private and root-owned")
    path=directory/"manifest.json"
    if path.is_symlink() or not path.is_file():raise ValueError("Missing pinned manifest")
    j=json.loads(path.read_text())
    if j.get("version")!=1 or j.get("id")!=name:
        raise ValueError("Manifest version or id mismatch")
    files=j.get("files")
    if not isinstance(files,dict) or not 1<=len(files)<=3 or not set(files)<=set(LIVE):
        raise ValueError("Unexpected config paths in manifest")
    for key,v in files.items():
        allowed={"expected_sha256","candidate_sha256"} | ({"scope"} if key=="dns" else set())
        if not {"expected_sha256","candidate_sha256"}<=set(v) or not set(v)<=allowed:
            raise ValueError("Config manifest key not allowlisted")
        if key=="dns" and v.get("scope","additive") not in ("additive","google"):
            raise ValueError("DNS policy scope not approved")
        if any(not SHA.fullmatch(v[h]) for h in ("expected_sha256","candidate_sha256")):
            raise ValueError("Invalid pinned SHA256")
    return files

def new_transaction(files):
    key=uuid.uuid4().hex[:16]
    directory=TXROOT/key
    directory.mkdir(mode=0o700)
    fsync_dir(TXROOT)
    return key,directory

def systemd_files(key,deadline,tx):
    unit=UNITPREFIX+key
    cmdline="/usr/bin/python3 "+str(INSTALL/"mnebydns_safe_deploy.py")+" recover "+str(tx)
    service,timer=persistent_watchdog(unit,deadline,cmdline)
    folder=Path("/etc/systemd/system")
    servicepath=folder/(unit+".service")
    timerpath=folder/(unit+".timer")
    if servicepath.exists() or timerpath.exists():
        raise RuntimeError("Recovery unit collision")
    try:
        write_durable(servicepath,service.encode(),0o644)
        write_durable(timerpath,timer.encode(),0o644)
        cmd("systemctl","daemon-reload")
        cmd("systemctl","enable","--now",unit+".timer",timeout=18)
        cmd("systemctl","is-active","--quiet",unit+".timer",timeout=8)
    except Exception:
        # If disarming fails, leave the watchdog intact to protect the stage.
        if servicepath.exists() and not timerpath.exists():servicepath.unlink()
        raise
    return unit

def coredns_pid():
    value=cmd("systemctl","show","--value","-p","MainPID",SERVICE["dns"])
    if not value.isdigit() or int(value)<1:
        raise RuntimeError("CoreDNS MainPID unavailable")
    return value


def ensure_hot_reload_config(data: bytes):
    if b"    reload 5s 1s" not in data:
        raise RuntimeError("Refuse CoreDNS update without hot reload plugin")
    p=subprocess.run(["/opt/mnebydns-dot/coredns","-plugins"],
                     text=True,capture_output=True,timeout=10)
    if p.returncode or not re.search(r"(?m)(^|\s)reload(\s|$)",p.stdout+p.stderr):
        raise RuntimeError("CoreDNS reload plugin unavailable")


def hot_reload_dns():
    old=coredns_pid()
    ensure_hot_reload_config(LIVE["dns"].read_bytes())
    time.sleep(7)
    if coredns_pid()!=old:
        raise RuntimeError("CoreDNS PID changed during hot reload")
    require_services_healthy({"dns"})


def revert_services(files):
    # Reload only what this transaction actually touched.
    for key in ("shared","pilot","dns"):
        if key not in files:continue
        if key=="shared":
            cmd("/usr/sbin/nginx","-t",timeout=15)
            cmd("systemctl","reload",SERVICE[key],timeout=20)
        elif key=="pilot":
            cmd("/usr/sbin/nginx","-t","-c",str(LIVE[key]),timeout=15)
            cmd("/usr/sbin/nginx","-s","reload","-c",str(LIVE[key]),timeout=20)
        else:
            if services_ok({"dns"})["dns"]["service_active"]:
                hot_reload_dns()
            else:
                # Recovery exception: a stopped resolver cannot hot reload.
                ensure_hot_reload_config(LIVE["dns"].read_bytes())
                cmd("systemctl","start",SERVICE["dns"],timeout=35)
                require_services_healthy({"dns"})

def tx_read(tx):
    if tx.parent!=TXROOT or not re.fullmatch("[0-9a-f]{16}",tx.name):
        raise ValueError("Invalid recovery path")
    if tx.is_symlink() or not tx.is_dir():raise ValueError("No prepared transaction")
    p=tx/"state.json"
    if p.is_symlink():raise ValueError("Untrusted state record")
    j=json.loads(p.read_text())
    if j.get("version")!=1 or not isinstance(j.get("files"),dict):
        raise ValueError("Unrecognized transaction format")
    return j

def recover_locked(tx):
    if (tx/"COMMITTED").is_file():
        return {"committed":True,"rolled_back":False}
    if (tx/"ROLLED_BACK").is_file():
        return {"committed":False,"rolled_back":True}
    record=tx_read(tx)
    files={}
    for key,info in record["files"].items():
        if key not in LIVE:raise ValueError("Unrecognized recover file")
        backup=tx/(key+".before")
        bs=backup.read_bytes()
        files[key]=(LIVE[key],state_from(info["before"]),
                    state_from(info["staged"]),bs)
    actions=conditional_rollback(files)
    changed=[k for k,action in actions.items() if action=="restore"]
    if changed:
        revert_services(changed)
    require_services_healthy(set(files)|{"dns","pilot","shared"})
    if "dns" in changed:
        ensure_dns_reader_access()
        smoke_check()
    write_durable(tx/"ROLLED_BACK",b"rollback complete\n")
    return {"committed":False,"rolled_back":True,"files":sorted(actions)}

def recover(tx):
    verify_system()
    with route_lock():
        result=recover_locked(tx)
    print(json.dumps({"operation":"recover","tx":tx.name,**result},sort_keys=True))

def apply(name):
    verify_system()
    manifest=manifest_for(name)
    with route_lock():
        require_services_healthy(set(SERVICE))
        ensure_dns_reader_access()
        prepared={}
        for key,pins in manifest.items():
            state,old=regular_read(LIVE[key])
            if state.sha256!=pins["expected_sha256"]:
                raise RuntimeError("Live configuration changed; "+key)
            newpath=STAGE/name/(key+".new")
            if newpath.is_symlink() or newpath.parent.resolve()!= (STAGE/name).resolve():
                raise RuntimeError("Untrusted staged candidate")
            _,payload=regular_read(newpath)
            if digest(payload)!=pins["candidate_sha256"]:
                raise RuntimeError("Proposed configuration hash mismatch")
            if payload!=old:
                prepared[key]=(state,old,payload)
        if not prepared:
            print(json.dumps({"done":True,"changed":False,
                              "reason":"payload_identical_to_live","files":sorted(manifest)}))
            return
        if "dns" in prepared:
            old=prepared["dns"][1]
            new=prepared["dns"][2]
            preserved(old,new,scope=manifest["dns"].get("scope","additive"))
            ensure_hot_reload_config(old)
            ensure_hot_reload_config(new)
            smoke_check()
        # Validate Nginx before swapping any live file.
        for key,(_,_,payload) in prepared.items():
            if key in ("shared","pilot"):
                draft=STAGE/name/(key+".new")
                cmd("/usr/sbin/nginx","-t","-c",str(draft),timeout=20)
        key,tx=new_transaction(prepared)
        record={"version":1,"id":key,"files":{}}
        for n,(state,old,payload) in prepared.items():
            write_durable(tx/(n+".before"),old)
            stage=replace(state,sha256=digest(payload))
            record["files"][n]={"before":state_obj(state),"staged":state_obj(stage)}
        write_durable(tx/"state.json",(json.dumps(record,sort_keys=True)+"\n").encode())
        unit=None
        try:
            # The persistent calendar unit must be active before any live write.
            unit=systemd_files(key,datetime.now(timezone.utc)+timedelta(minutes=8),tx)
            for n,(state,old,payload) in prepared.items():
                atomic_replace(LIVE[n],state,payload)
            revert_services(prepared)
            healthy=require_services_healthy(set(SERVICE))
            ensure_dns_reader_access()
            if "dns" in prepared:
                smoke_check()
            for n,(_,_,payload) in prepared.items():
                if digest(payload)!=capture(LIVE[n]).sha256:
                    raise RuntimeError("Published config changed during activation")
            commit_marker(tx,{n:digest(v[2]) for n,v in prepared.items()})
            # COMMITTED is fsync-durable; watchdog recovery treats it as final.
            # Failure to disable an obsolete timer is NOT a failed deployment.
            disarmed=True
            try:
                cmd("systemctl","disable","--now",unit+".timer",timeout=16)
            except Exception:
                disarmed=False
            print(json.dumps({"done":True,"changed":True,
                  "files":sorted(prepared),"healthy":healthy,"committed":True,
                  "watchdog_disarmed":disarmed,"transaction_id":key},sort_keys=True))
        except Exception:
            if unit:
                try:
                    recover_locked(tx)
                    cmd("systemctl","disable","--now",unit+".timer",timeout=16)
                except Exception:
                    # Keep persistent watchdog: it will recover after reboot.
                    pass
            raise

def owner_publish(phase: str, base: Path, kind: str):
    """Publish owner-domain canary while caller holds shared route lock."""
    verify_system()
    if phase not in ("stage","rollback") or kind not in ("dns","nginx"):
        raise ValueError("Unapproved owner-domain transition")
    parent=OWNERROOT
    if (base.parent!=parent or not re.fullmatch(r"[0-9]{9,13}",base.name)
            or base.is_symlink() or not base.is_dir()):
        raise ValueError("Owner-domain checkpoint path untrusted")
    if base.stat().st_uid!=0 or stat.S_IMODE(base.stat().st_mode)!=0o700:
        raise ValueError("Owner-domain checkpoint must be private and root-owned")
    name="dns" if kind=="dns" else "shared"
    live=LIVE[name]
    before=base/(kind+".before")
    pilot=base/(kind+".pilot")
    source,target=(before,pilot) if phase=="stage" else (pilot,before)
    for candidate in (source,target):
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_uid!=0:
            raise ValueError("Untrusted owner-domain candidate")
    original=source.read_bytes()
    changed=target.read_bytes()
    if kind=="dns":
        ensure_dns_reader_access()
        domain_file=base/"domain"
        if not domain_file.is_file() or domain_file.is_symlink():
            raise ValueError("Owner-domain exact hostname missing")
        domain=domain_file.read_text().strip()
        if not re.fullmatch(r"[a-z0-9.-]{4,253}",domain):
            raise ValueError("Owner domain invalid")
        preserved(original,changed,scope="owner",owner_domain=domain)
        ensure_hot_reload_config(original)
        ensure_hot_reload_config(changed)
    live_state,old=regular_read(live)
    if old==changed:
        print(json.dumps({"done":True,"changed":False,"kind":kind,"phase":phase}))
        return
    if old!=original:
        raise RuntimeError("Owner-domain canary source does not match live file")
    # Caller stage/rollback already holds /run/lock/mnebyvpn-public-route.lock.
    new_state=atomic_replace(live,live_state,changed)
    if kind=="dns":
        ensure_dns_reader_access()
    if new_state.sha256!=digest(changed):
        raise RuntimeError("Owner-domain atomic config verification failed")
    print(json.dumps({"done":True,"changed":True,"kind":kind,"phase":phase}))


def status():
    verify_system()
    live={}
    for name,path in LIVE.items():
        s=capture(path)
        live[name]={"exists":True,"sha256":s.sha256,"mode":oct(s.mode),
                    "owner_uid":s.uid,"owner_gid":s.gid}
    ensure_dns_reader_access()
    print(json.dumps({"read_only":True,"files":live,
        "services":services_ok(set(SERVICE)),
        "dns_reader_group_verified":True,
        "installer_version":"2026-11-16-safe-deploy-v3"},sort_keys=True))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("command",choices=("status","apply","recover","owner-publish"))
    parser.add_argument("arg",nargs="?")
    parser.add_argument("extra",nargs="*")
    args=parser.parse_args()
    if args.command=="status":
        if args.arg:parser.error("status does not take arguments")
        status()
    elif args.command=="apply":
        if not args.arg:parser.error("apply requires pinned manifest id")
        apply(args.arg)
    elif args.command=="owner-publish":
        if not args.arg or len(args.extra)!=2:
            parser.error("owner-publish requires phase, checkpoint, kind")
        owner_publish(args.arg,Path(args.extra[0]),args.extra[1])
    else:
        if not args.arg:parser.error("recover requires transaction path")
        tx=Path(args.arg)
        if tx.resolve().parent!=TXROOT:raise ValueError("Recovery folder outside transaction root")
        recover(tx)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(json.dumps({"done":False,"error":type(exc).__name__,
                          "reason":str(exc)[:150]}),flush=True)
        raise SystemExit(1)
