#!/usr/bin/env python3
"""FI217: pin and stage three Python production validators while AWG is OFF.

Only changes exact reviewed source files. No systemd starts/restarts/enables,
manifest edits, client grants, firewall changes, or RU188 publication.
Old bytes are retained durably for a separately reviewed rollback.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

import awg_lifecycle
import install_components

FI_IP="217.11.167.91"
NODE="fi-test-01"
ROOT=Path("/var/lib/mnebyvpn-nodekit")
APP=Path("/opt/mnebyvpn-nodekit")
BACKUPS=APP/".fi217-production-validators-backup"
LOCK=APP/".fi217-production-source.lock"
UNITS=(
    "mnebyvpn-nodekit-awg@fi-test-01.service",
    "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
)
TIMERS=(
    "fi-awg-disposable-apply-expiry.timer",
    "nodekit-fi-awg-canary-expiry.timer",
)
FILES=("install_components.py","awg_lifecycle.py")
HELPER="fi_awg_production_policy.py"
MAX_BYTES=100000

class Refused(ValueError):
    pass

def refuse(reason:str)->None:
    raise Refused(reason)

def command(args:list[str],timeout:int=8)->subprocess.CompletedProcess:
    try:
        return subprocess.run(args,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        refuse("UNAVAILABLE")

def secure_file(path:Path, *, require:bool)->bytes|None:
    if path.is_symlink():
        refuse("SYMLINK")
    if not path.exists():
        if require:refuse("MISSING")
        return None
    info=path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
        info.st_mode & 0o077 or info.st_nlink!=1 or
        not 1<=info.st_size<=MAX_BYTES):
        refuse("UNTRUSTED_FILE")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        actual=os.fstat(fd)
        if (actual.st_ino!=info.st_ino or actual.st_dev!=info.st_dev or
            actual.st_size!=info.st_size):
            refuse("SOURCE_CHANGED")
        data=os.read(fd,MAX_BYTES+1)
        if len(data)!=info.st_size:refuse("SOURCE_CHANGED")
        return data
    finally:os.close(fd)

def secure_directory(path:Path)->None:
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or
        info.st_mode & 0o022):
        refuse("DIRECTORY_UNTRUSTED")

def require_dormant()->None:
    if os.geteuid()!=0:refuse("ROOT_REQUIRED")
    addr=command(["/usr/sbin/ip","-o","-4","addr","show"])
    if addr.returncode!=0 or not re.search(
        r"(?:^|\s)"+re.escape(FI_IP)+r"/\d{1,2}(?:\s|$)",addr.stdout):
        refuse("WRONG_FI_NODE")
    secure_directory(APP)
    secure_directory(ROOT)
    secure_directory(ROOT/NODE)
    for service in UNITS+TIMERS:
        state=command(["/usr/bin/systemctl","show","-P","ActiveState",service])
        if state.returncode or state.stdout.strip()!="inactive":
            refuse("AWG_OR_EXPIRY_ACTIVE")
    for service in UNITS:
        if command(["/usr/bin/systemctl","is-enabled","--quiet",service]).returncode==0:
            refuse("AWG_AUTOSTART_ENABLED")
    if (Path("/sys/class/net/awg0").exists() or
        (ROOT/NODE/"amneziawg/peer-grants.json").exists() or
        (ROOT/NODE/"amneziawg/peer-grants.json").is_symlink() or
        Path("/run/nodekit-fi-awg-external.json").exists()):
        refuse("AWG_RUNTIME_OR_CUSTOMERS_EXIST")
    # Use uploaded, reviewed code to validate the old STAGED config and
    # pinned three AWG binaries, without activating any listener or peer.
    node=install_components.node_ready(ROOT,NODE)
    report=awg_lifecycle.validate(node)
    if report.get("mode")!="staged" or report.get("zero_peers") is not True:
        refuse("NODE_NOT_UNPUBLISHED")
    unit=awg_lifecycle.UNIT_PATH
    if unit.is_symlink() or not unit.is_file() or unit.read_text()!=awg_lifecycle.unit_source():
        refuse("SYSTEMD_UNIT_DRIFT")

def sources(folder:Path)->dict[str,tuple[bytes,bytes|None]]:
    secure_directory(folder)
    result={}
    for name in FILES:
        old=secure_file(folder/("legacy_"+name),require=True)
        new=secure_file(folder/name,require=True)
        if old==new:refuse("NEW_SOURCE_NOT_DISTINCT")
        result[name]=(new,old)
    result[HELPER]=(secure_file(folder/HELPER,require=True),None)
    return result

def status(expected:dict)->str:
    old_count=0
    new_count=0
    for name,(new,old) in expected.items():
        found=secure_file(APP/name,require=name in FILES)
        if found==new:
            new_count+=1
        elif old is not None and found==old:
            old_count+=1
        elif found is None and name==HELPER:
            old_count+=1
        else:
            refuse("UNREVIEWED_INSTALLED_CODE")
    if old_count==len(expected):return "LEGACY"
    if new_count==len(expected):return "PINNED_STAGED"
    return "PARTIAL_PINNED_STAGING"

def backups(expected:dict, *, create:bool)->None:
    if not BACKUPS.exists():
        if not create:refuse("MISSING_BACKUPS")
        BACKUPS.mkdir(mode=0o700)
    secure_directory(BACKUPS)
    if BACKUPS.stat().st_mode & 0o077:refuse("BACKUP_PERMISSIONS")
    for name in FILES:
        old=expected[name][1]
        assert old is not None
        destination=BACKUPS/(name+".legacy")
        existing=secure_file(destination,require=False)
        if existing is None:
            if not create:refuse("MISSING_BACKUP")
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                       os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            with os.fdopen(fd,"wb") as handle:
                handle.write(old)
                handle.flush()
                os.fsync(handle.fileno())
        elif existing!=old:
            refuse("BACKUP_DRIFT")
        if secure_file(destination,require=True)!=old:
            refuse("BACKUP_VERIFY_FAILED")
    fd=os.open(BACKUPS,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def replace_atomically(path:Path,payload:bytes)->None:
    fd,temp=tempfile.mkstemp(prefix=".fi-awg-pinned-",dir=APP)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        require_dormant()
        # Unknown changed content is never overwritten, even mid-update.
        os.replace(temp,path)
        directory=os.open(APP,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:Path(temp).unlink(missing_ok=True)

def locked_stage(folder:Path, *, verify_only:bool)->str:
    require_dormant()
    expected=sources(folder)
    current=status(expected)
    if verify_only:
        if current=="PINNED_STAGED":
            backups(expected,create=False)
        return current
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
            info.st_mode & 0o077 or info.st_nlink!=1):
            refuse("LOCK_UNTRUSTED")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require_dormant()
        current=status(expected)
        backups(expected,create=True)
        if current!="PINNED_STAGED":
            for name,(new,old) in expected.items():
                installed=secure_file(APP/name,require=name in FILES)
                if installed==new:continue
                if installed!=old:refuse("UNEXPECTED_SOURCE_CHANGE")
                replace_atomically(APP/name,new)
        require_dormant()
        if status(expected)!="PINNED_STAGED":
            refuse("POST_INSTALL_VERIFY_FAILED")
        backups(expected,create=False)
        return "PINNED_STAGED"
    finally:
        try:fcntl.flock(fd,fcntl.LOCK_UN)
        finally:os.close(fd)

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("stage","verify"),required=True)
    parser.add_argument("--folder",type=Path,required=True)
    args=parser.parse_args()
    try:
        state=locked_stage(args.folder,verify_only=args.mode=="verify")
        print("FI_AWG_PRODUCTION_SOURCE="+state+
              ";AWG_ACTIVE=false;WORKER_ACTIVE=false;CUSTOMER_RELEASE=false")
        return 0
    except (Refused,OSError,ValueError,TypeError,KeyError,
            subprocess.SubprocessError,BlockingIOError):
        print("FI_AWG_PRODUCTION_SOURCE=BLOCKED;"
              "AWG_UNCHANGED_OR_NOT_VERIFIED=true;CUSTOMER_RELEASE=false")
        return 2

if __name__=="__main__":
    sys.exit(main())
