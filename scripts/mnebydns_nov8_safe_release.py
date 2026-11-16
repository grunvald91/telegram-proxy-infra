#!/usr/bin/env python3
"""Guarded production release coordinator for MNEBYDNS configs.

Install under /opt/mnebydns-safe-deploy/release.py together with
mnebydns_nov8_restore_safety.py. Installation/inspect never change DNS.
A future owner-approved release supplies a pinned manifest and new files.
Persistent calendar rollback is installed BEFORE any live config change.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from mnebydns_nov8_restore_safety import (
    FileState, atomic_replace, capture, commit_marker, conditional_rollback,
    digest, persistent_watchdog, route_lock,
)

ROOT=Path("/opt/mnebydns-safe-deploy")
CHECKPOINTS=ROOT/"checkpoints"
FILES={
    "dns":Path("/opt/mnebydns-dot/Corefile"),
    "shared":Path("/etc/nginx/nginx.conf"),
    "pilot":Path("/etc/mnebydns-googlepilot/nginx.conf"),
}
SERVICE={"dns":"mnebydns-dot.service",
         "shared":"nginx.service","pilot":"mnebydns-googlepilot.service"}
LISTEN={"dns":853,"shared":443,"pilot":15449}
ID=re.compile(r"[a-z][a-z0-9-]{4,38}\Z")
SHA=re.compile(r"[0-9a-f]{64}\Z")


def run(*args, timeout=18):
    p=subprocess.run(list(args),capture_output=True,text=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError("Failed command "+args[0]+" "+args[1]+": rc="+str(p.returncode))
    return p.stdout.strip()


def ready(name):
    if subprocess.run(["systemctl","is-active","--quiet",SERVICE[name]],
                      capture_output=True,timeout=7).returncode!=0:
        return False
    p=subprocess.run(["ss","-H","-lnt","sport = :"+str(LISTEN[name])],
                     capture_output=True,text=True,timeout=7)
    return p.returncode==0 and bool(p.stdout.strip())


def wait_ready(names, max_seconds=10):
    deadline=time.monotonic()+max_seconds
    while time.monotonic()<deadline:
        if all(ready(x) for x in names):return
        time.sleep(.4)
    raise RuntimeError("Required production service/listener not ready")


def state_dict(s):
    return {"sha256":s.sha256,"uid":s.uid,"gid":s.gid,"mode":s.mode,
            "xattrs":[[k,base64.b64encode(v).decode()] for k,v in s.xattrs]}


def state_from(d):
    return FileState(d["sha256"],int(d["uid"]),int(d["gid"]),int(d["mode"]),
                     tuple((k,base64.b64decode(v,validate=True)) for k,v in d["xattrs"]))


def durable_write(p, data):
    p=Path(p)
    fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        os.write(fd,data)
        os.fsync(fd)
    finally:os.close(fd)
    dirfd=os.open(p.parent,os.O_DIRECTORY|os.O_RDONLY)
    try:os.fsync(dirfd)
    finally:os.close(dirfd)


def manifest(root):
    m=json.loads((Path(root)/"release.json").read_text())
    if m.get("schema")!=1 or not ID.fullmatch(m.get("id","")):
        raise ValueError("Invalid release ID/schema")
    if set(m)!={"schema","id","expected","new"}:
        raise ValueError("Unexpected manifest fields")
    if set(m["expected"])!=set(FILES) or not m["new"] or not set(m["new"])<=set(FILES):
        raise ValueError("Manifest must pin all live files and one or more new files")
    if any(not SHA.fullmatch(v) for v in (*m["expected"].values(),*m["new"].values())):
        raise ValueError("Malformed pinned sha256")
    return m


def assert_dns_reader():
    s=capture(FILES["dns"])
    group=grp.getgrnam("mnebydns-corefile-readers").gr_gid
    if s.gid!=group or s.uid!=0 or s.mode!=0o640:
        raise RuntimeError("CoreDNS access metadata not root:reader 0640")
    props=run("systemctl","show",SERVICE["dns"],
              "-p","DynamicUser,SupplementaryGroups,User")
    if "DynamicUser=yes" not in props or "mnebydns-corefile-readers" not in props:
        raise RuntimeError("CoreDNS reader-group unit policy missing")


def audit():
    all_states={k:capture(v) for k,v in FILES.items()}
    assert_dns_reader()
    wait_ready(FILES.keys(),max_seconds=3)
    # Never log individual users, keys, credentials, or config contents.
    print(json.dumps({
        "mode":"audit","ok":True,"read_only":True,
        "services":{k:"active" for k in SERVICE},
        "tcp_listeners":{k:LISTEN[k] for k in LISTEN},
        "configuration_hashes":{k:s.sha256 for k,s in all_states.items()},
        "dns_reader_group_verified":True,
    },sort_keys=True))


def validate_stage(folder):
    folder=Path(folder)
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Stage must be a real directory")
    m=manifest(folder)
    staged={}
    for k,expected in m["new"].items():
        p=folder/(k+".new")
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 800000 or p.stat().st_size==0:
            raise ValueError("Invalid staged file")
        data=p.read_bytes()
        if digest(data)!=expected:raise ValueError("Staged hash mismatch")
        staged[k]=data
    for k in FILES:
        if capture(FILES[k]).sha256!=m["expected"][k]:
            raise RuntimeError("Live "+k+" changed since approval")
    # Prevent silently changing CoreDNS group; readers use group-only mode.
    assert_dns_reader()
    return m,staged


def stage_manifest(m, current, payloads, root):
    root=Path(root)
    if root.exists():raise RuntimeError("Checkpoint ID already used")
    root.mkdir(mode=0o700,parents=True)
    payload={"id":m["id"],"schema":1,"changed":sorted(payloads),"expected":m["expected"],
             "new":m["new"],"states":{k:state_dict(s) for k,s in current.items()},
             "created_utc":datetime.now(timezone.utc).isoformat()}
    durable_write(root/"state.json",(json.dumps(payload,sort_keys=True)+"\n").encode())
    for k,blob in payloads.items():
        durable_write(root/(k+".before"),FILES[k].read_bytes())
        durable_write(root/(k+".after"),blob)
    return payload


def installed_watchdog(identifier, root, deadline):
    unit="mnebydns-safe-rollback-"+identifier
    command="/usr/bin/python3 /opt/mnebydns-safe-deploy/release.py rollback "+identifier
    service,timer=persistent_watchdog(unit,deadline,command)
    systemd=Path("/etc/systemd/system")
    for suffix,content in (("service",service),("timer",timer)):
        dest=systemd/(unit+"."+suffix)
        durable_write(dest,content.encode())
        os.chmod(dest,0o644)
    run("systemctl","daemon-reload")
    run("systemctl","enable","--now",unit+".timer")
    if run("systemctl","is-active",unit+".timer")!="active":
        raise RuntimeError("Persistent recovery timer failed to arm")
    return unit


def reread(root):
    root=Path(root)
    state=json.loads((root/"state.json").read_text())
    if not ID.fullmatch(state["id"]) or state["schema"]!=1 or not set(state["changed"])<=set(FILES):
        raise RuntimeError("Corrupt checkpoint")
    files={}
    for k in state["changed"]:
        old=state_from(state["states"][k])
        before=(root/(k+".before")).read_bytes()
        after=(root/(k+".after")).read_bytes()
        if digest(before)!=old.sha256 or digest(after)!=state["new"][k]:
            raise RuntimeError("Checkpoint data changed")
        staged=FileState(digest(after),old.uid,old.gid,old.mode,old.xattrs)
        files[k]=(FILES[k],old,staged,before)
    return files,state


def reload_services(keys):
    keys=set(keys)
    # Preserve existing DoT sessions using preinstalled 5s CoreDNS reload
    # plugin. Reject Corefile changes when hot reload is not configured.
    if "shared" in keys:
        run("/usr/sbin/nginx","-t")
        run("systemctl","reload",SERVICE["shared"])
    if "pilot" in keys:
        run("/usr/sbin/nginx","-t","-c",str(FILES["pilot"]))
        run("/usr/sbin/nginx","-s","reload","-c",str(FILES["pilot"]))
    if "dns" in keys:
        dns=FILES["dns"].read_text()
        if "    reload 5s 1s" not in dns:
            raise RuntimeError("DNS hot reload required to avoid disconnecting clients")
        # CoreDNS reload plugin notices changes without a service restart.
        time.sleep(7)
    wait_ready(FILES.keys(),max_seconds=7)


def rollback(identifier):
    root=CHECKPOINTS/identifier
    if not ID.fullmatch(identifier) or not root.is_dir() or root.is_symlink():
        raise ValueError("Bad recovery checkpoint")
    with route_lock():
        if (root/"COMMITTED").exists():
            print(json.dumps({"mode":"rollback","committed":True,"changed":False}))
            return
        files,state=reread(root)
        actions=conditional_rollback(files)
        modified=[key for key,act in actions.items() if act=="restore"]
        if modified:
            reload_services(modified)
        # Never mark committed during rollback, the watchdog can run again if
        # service verification fails or another process holds the lock.
        if not (root/"ROLLED_BACK").exists():
            durable_write(root/"ROLLED_BACK",(json.dumps(actions)+"\n").encode())
        print(json.dumps({"mode":"rollback","done":True,"actions":actions},sort_keys=True))


def apply(folder):
    if os.geteuid()!=0:raise PermissionError("Root required")
    with route_lock():
        m,new=validate_stage(folder)
        full_state={k:capture(p) for k,p in FILES.items()}
        # Strict no-op operation cannot create an owner or watchdog.
        changed={k:data for k,data in new.items() if digest(data)!=full_state[k].sha256}
        if not changed:
            # A genuine no-op must not arm a timer or reload production.
            wait_ready(FILES.keys(),max_seconds=3)
            print(json.dumps({"mode":"apply","changed":False,"done":True,"id":m["id"],
                              "corefile_hash_unchanged":True},sort_keys=True))
            return
        wait_ready(FILES.keys(),max_seconds=3)
        root=CHECKPOINTS/m["id"]
        stage_manifest(m,full_state,changed,root)
        # Stage nginx candidates before arming the timer or changing anything.
        for k in ("shared","pilot"):
            if k in changed:
                run("/usr/sbin/nginx","-t","-c",str(root/(k+".after")))
        unit=installed_watchdog(m["id"],root,datetime.now(timezone.utc)+timedelta(minutes=8))
        try:
            for k,blob in changed.items():
                if capture(FILES[k])!=full_state[k]:
                    raise RuntimeError("Live config drift before apply")
                expected_after=atomic_replace(FILES[k],full_state[k],blob)
                if expected_after.sha256!=digest(blob):
                    raise RuntimeError("Staged hash mismatch after install")
            reload_services(changed)
            for k,v in changed.items():
                if capture(FILES[k]).sha256!=digest(v):
                    raise RuntimeError("Live config drift after reload")
            commit_marker(root,{k:digest(v) for k,v in changed.items()})
            # A committed canary should not revert after reboot.
            run("systemctl","disable","--now",unit+".timer")
            print(json.dumps({"mode":"apply","done":True,"changed":sorted(changed),
                              "rollback_armed":False,"id":m["id"]},sort_keys=True))
        except Exception:
            # The persistent timer stays armed unless rollback is complete.
            files,_=reread(root)
            try:
                actions=conditional_rollback(files)
                reload_services(k for k,v in actions.items() if v=="restore")
                # Unarm only after validated rollback.
                run("systemctl","disable","--now",unit+".timer")
                print(json.dumps({"mode":"apply","rolled_back":True,"id":m["id"]}))
            except Exception as exc:
                print(json.dumps({"mode":"apply","rollback_pending":True,
                                  "error_type":type(exc).__name__}))
            raise


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=("audit","apply","rollback"))
    parser.add_argument("argument",nargs="?")
    a=parser.parse_args()
    if a.action=="audit":
        if a.argument:parser.error("audit takes no args")
        audit()
    elif a.action=="apply":
        if not a.argument:parser.error("apply needs staged directory")
        apply(Path(a.argument))
    else:
        if not a.argument:parser.error("rollback needs checkpoint id")
        rollback(a.argument)
if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(json.dumps({"mode":"release","ok":False,
                          "error":type(exc).__name__,"message":str(exc)[:160]}))
        raise SystemExit(1)
