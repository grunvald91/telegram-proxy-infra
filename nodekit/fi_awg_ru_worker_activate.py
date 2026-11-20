#!/usr/bin/env python3
"""RU188: start exactly reviewed six-module FI217 AWG worker under systemd.

No client release, no billing override and no synchronous per-packet access.
Root-owned approval marker is required by existing systemd; a failed start
removes only our marker/boot link and leaves existing controller untouched.
"""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import fi_awg_client_worker_cutover as pinned
import fi_awg_worker_source_stage as trust
import fi_awg_worker_isolated_systemd_stage as unit

SERVICE="mnebyvpn-awg-delivery.service"
APPROVAL=trust.ROOT/"approvals/awg-delivery.enable"
WANTS=Path("/etc/systemd/system/multi-user.target.wants")/SERVICE
BASE=Path("/etc/systemd/system")/SERVICE
LOCK=trust.ROOT/"awg-delivery-live-activation.lock"
MARKER=b"FI217_AWG_WORKER_OWNER_APPROVED_V1\n"

class Blocked(ValueError):pass

def cmd(args:list[str],*,check:bool=True,timeout:int=22):
    return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,check=check,timeout=timeout)

def active()->bool:
    return cmd(["systemctl","is-active","--quiet",SERVICE],check=False).returncode==0

def ensure_marker()->None:
    if APPROVAL.is_symlink() or APPROVAL.exists():
        raise Blocked("approval marker already present")
    trust.safe_directory(APPROVAL.parent)
    fd=os.open(APPROVAL,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(MARKER);f.flush();os.fsync(f.fileno())
    if APPROVAL.read_bytes()!=MARKER:raise Blocked("approval write differs")

def effective_pinned()->None:
    trust.require_safe_dormant()
    # pinned.verify() checks the actual six-source effective systemd unit,
    # including exact WorkingDirectory and argv. The earlier 3/5-module
    # isolated.systemd exact_effective_unit() is deliberately NOT used.
    pinned.verify()
    unit.approved_base_unit()
    if unit.show("WorkingDirectory")!="/opt/mnebyvpn-controller/awg-worker-releases/446c331249085adb6536e3d9913fb4b68abf6cd7":
        raise Blocked("unexpected worker release")

def verify()->None:
    if not trust.is_ru188():raise Blocked("wrong controller")
    if not active():raise Blocked("worker inactive")
    if APPROVAL.is_symlink() or not APPROVAL.is_file():
        raise Blocked("missing approval")
    meta=APPROVAL.stat()
    if meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o600 or APPROVAL.read_bytes()!=MARKER:
        raise Blocked("approval untrusted")
    if not WANTS.is_symlink() or WANTS.resolve(strict=True)!=BASE:
        raise Blocked("worker boot link missing")
    if unit.show("WorkingDirectory")!="/opt/mnebyvpn-controller/awg-worker-releases/446c331249085adb6536e3d9913fb4b68abf6cd7":
        raise Blocked("wrong worker")
    if int(unit.show("MainPID"))<=1:raise Blocked("no worker process")
    if unit.show("SubState")!="running":raise Blocked("worker not running")

def rollback(created_marker:bool,created_link:bool)->None:
    cmd(["systemctl","stop",SERVICE],check=False,timeout=25)
    if created_link and WANTS.is_symlink() and WANTS.resolve(strict=True)==BASE:
        WANTS.unlink()
        cmd(["systemctl","daemon-reload"],check=False,timeout=15)
    if created_marker and APPROVAL.is_file() and not APPROVAL.is_symlink() and APPROVAL.read_bytes()==MARKER:
        APPROVAL.unlink()

def start()->str:
    if active():
        verify();return "ALREADY_ACTIVE"
    effective_pinned()
    if WANTS.exists() or WANTS.is_symlink():
        raise Blocked("unexpected worker boot link")
    marker=False
    linked=False
    try:
        ensure_marker();marker=True
        cmd(["systemctl","add-wants","multi-user.target",SERVICE])
        if not WANTS.is_symlink() or WANTS.resolve(strict=True)!=BASE:
            raise Blocked("unrecognized boot activation")
        linked=True
        cmd(["systemctl","start",SERVICE],timeout=40)
        time.sleep(4)
        verify()
        return "ACTIVE"
    except BaseException:
        rollback(marker,linked)
        raise

def main()->int:
    args=argparse.ArgumentParser()
    args.add_argument("--mode",choices=("start","verify"),required=True)
    mode=args.parse_args().mode
    try:
        if os.geteuid()!=0 or not trust.is_ru188():raise Blocked("wrong host")
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            meta=os.fstat(fd)
            if (meta.st_uid!=0 or not stat.S_ISREG(meta.st_mode) or
                stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_nlink!=1):
                raise Blocked("untrusted lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            status=start() if mode=="start" else (verify() or "VERIFIED")
            print("FI_AWG_RU_WORKER="+status+";AUTOBOOT=true;CUSTOMER_RELEASE_UNCHANGED=true")
            return 0
        finally:os.close(fd)
    except (OSError,TypeError,ValueError,RuntimeError,subprocess.SubprocessError,
            trust.StageBlocked):
        print("FI_AWG_RU_WORKER=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
