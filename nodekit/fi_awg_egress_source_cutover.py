#!/usr/bin/env python3
"""FI217 signed AWG egress source cutover; ALWAYS service-inactive."""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import stat
import sys
import tempfile
from fi_awg_policy_source_stage import APP, Blocked, checked_dir, checked_file, git_blob_id
from fi_awg_egress_source_stage import PIN, NAME, require_dormant, verify as verify_stage

OLD="973ac8f222bf4eb32451b00fb9e8a10fa497903e"
TARGET=APP/"awg_egress.py"
BACKUP=APP/".fi217-awg-egress-legacy"
LOCK=Path("/run/lock/mnebyvpn-fi-awg-egress-cutover.lock")

def current()->str:
    if TARGET.is_symlink():raise Blocked("untrusted installed source")
    if not TARGET.exists():return "MISSING"
    sha=git_blob_id(checked_file(TARGET,private=True))
    if sha==OLD:return "LEGACY"
    if sha==PIN:return "NEW_INACTIVE"
    raise Blocked("unknown installed source")

def backup_ok()->None:
    if BACKUP.is_symlink():raise Blocked("backup symlink")
    if BACKUP.exists():
        checked_dir(BACKUP,private=True)
        if {p.name for p in BACKUP.iterdir()}!={"awg_egress.legacy.py"}:
            raise Blocked("unexpected backup contents")
        if git_blob_id(checked_file(BACKUP/"awg_egress.legacy.py",private=True))!=OLD:
            raise Blocked("legacy backup tampered")

def write_atomic(target:Path,payload:bytes,*,replace:bool)->None:
    fd,tmp=tempfile.mkstemp(prefix=".fi-awg-egress-",dir=target.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:os.replace(tmp,target)
        else:os.link(tmp,target,follow_symlinks=False)
    finally:Path(tmp).unlink(missing_ok=True)

def switch()->str:
    require_dormant()
    verify_stage(APP/"releases")
    backup_ok()
    before=current()
    if before=="NEW_INACTIVE":return "ALREADY_SELECTED"
    payload=checked_file(APP/"releases"/NAME/"awg_egress.py",private=True)
    if git_blob_id(payload)!=PIN:raise Blocked("unreviewed new source")
    old=None
    if before=="LEGACY":
        old=checked_file(TARGET,private=True)
        if git_blob_id(old)!=OLD:raise Blocked("unexpected legacy bytes")
        if not BACKUP.exists():BACKUP.mkdir(mode=0o700)
        checked_dir(BACKUP,private=True)
        if not (BACKUP/"awg_egress.legacy.py").exists():
            write_atomic(BACKUP/"awg_egress.legacy.py",old,replace=False)
        backup_ok()
    require_dormant()
    try:
        write_atomic(TARGET,payload,replace=before=="LEGACY")
        if current()!="NEW_INACTIVE":raise Blocked("source verification failed")
        require_dormant()
        return "NEW_INACTIVE"
    except BaseException:
        if old is not None and current()=="NEW_INACTIVE":
            write_atomic(TARGET,old,replace=True)
            if current()!="LEGACY":raise Blocked("rollback failed")
        elif before=="MISSING" and current()=="NEW_INACTIVE":
            TARGET.unlink()
        raise

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("inspect","switch","verify"),required=True)
    args=p.parse_args()
    try:
        require_dormant()
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            meta=os.fstat(fd)
            if (meta.st_uid!=0 or not stat.S_ISREG(meta.st_mode) or
                stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_nlink!=1):
                raise Blocked("untrusted lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.mode=="inspect":
                result=current()
                backup_ok()
            elif args.mode=="verify":
                verify_stage(APP/"releases")
                backup_ok()
                if current()!="NEW_INACTIVE":raise Blocked("not installed")
                result="VERIFIED"
            else:result=switch()
            require_dormant()
            print("FI_AWG_EGRESS_CUTOVER="+result+
                  ";AWG_ACTIVE=false;CODE_READY=true;CUSTOMER_RELEASE_UNCHANGED=true")
            return 0
        finally:os.close(fd)
    except (OSError,ValueError,TypeError) as exc:
        print("FI_AWG_EGRESS_CUTOVER=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
