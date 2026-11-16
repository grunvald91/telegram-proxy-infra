#!/usr/bin/env python3
"""Safety primitives for Nov-8 SmartDNS config restorations.

No production entrypoint. The original one-shot workflow remains archived.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile

@dataclass(frozen=True)
class FileState:
    sha256: str
    uid: int
    gid: int
    mode: int
    xattrs: tuple

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def capture(path: Path) -> FileState:
    p=Path(path)
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or p.is_symlink() or s.st_nlink != 1:
        raise ValueError("Expected regular nonlinked config")
    return FileState(
        digest(p.read_bytes()), s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode),
        tuple(sorted((k,os.getxattr(p,k,follow_symlinks=False))
                     for k in os.listxattr(p,follow_symlinks=False)))
    )

def same_metadata(a: FileState,b: FileState) -> bool:
    return (a.uid,a.gid,a.mode,a.xattrs)==(b.uid,b.gid,b.mode,b.xattrs)

def atomic_replace(path: Path, expected: FileState, new: bytes) -> FileState:
    """Compare expected bytes and all metadata; preserve ownership and ACL."""
    p=Path(path)
    if capture(p)!=expected:
        raise RuntimeError("Concurrent change; abort")
    fd=-1
    temp=None
    try:
        fd,name=tempfile.mkstemp(prefix="."+p.name+".nov8-",dir=p.parent)
        temp=Path(name)
        with os.fdopen(fd,"wb",closefd=False) as f:
            f.write(new)
            f.flush()
        os.fchown(fd,expected.uid,expected.gid)
        os.fchmod(fd,expected.mode)
        for k,v in expected.xattrs:
            os.setxattr(fd,k,v)
        os.fsync(fd)
        os.close(fd)
        fd=-1
        staged=capture(temp)
        if staged.sha256!=digest(new) or not same_metadata(staged,expected):
            raise RuntimeError("Staged file metadata differs")
        if capture(p)!=expected:
            raise RuntimeError("Production changed while staging")
        os.replace(temp,p)
        temp=None
        dirfd=os.open(p.parent,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        result=capture(p)
        if result.sha256!=digest(new) or not same_metadata(result,expected):
            raise RuntimeError("Post-replace validation failed")
        return result
    finally:
        if fd>=0:os.close(fd)
        if temp is not None:temp.unlink(missing_ok=True)

@contextmanager
def route_lock(path: Path=Path("/run/lock/mnebyvpn-public-route.lock")):
    if not path.is_absolute():
        raise ValueError("Lock path must be absolute")
    with open(path,"a+") as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:yield
        finally:fcntl.flock(fd,fcntl.LOCK_UN)

def conditional_rollback(files: dict) -> dict:
    """Caller holds route_lock; all files must be unchanged or own staged bytes.

    Mapping: name -> (live_path, before_state, own_staged_state, before_bytes).
    """
    plans={}
    for name,(path,before,staged,backup) in files.items():
        if digest(backup)!=before.sha256:
            raise RuntimeError("Backup hash mismatch")
        now=capture(path)
        if now==before:plans[name]="unchanged"
        elif now==staged:plans[name]="restore"
        else:raise RuntimeError("Third-party config change; refuse rollback")
    for name,action in plans.items():
        if action=="restore":
            path,before,staged,backup=files[name]
            if atomic_replace(path,staged,backup)!=before:
                raise RuntimeError("Rollback metadata mismatch")
    return plans

def persistent_watchdog(unit: str,deadline: datetime,command: str) -> tuple[str,str]:
    """Render a reboot-persistent calendar watchdog; no install is done here."""
    if not re.fullmatch(r"mnebydns-[a-z0-9-]{3,72}",unit):
        raise ValueError("Bad unit name")
    if deadline.tzinfo is None or deadline<=datetime.now(timezone.utc):
        raise ValueError("Deadline must be future UTC")
    if not command.startswith("/usr/bin/python3 /"):
        raise ValueError("Absolute approved recovery command required")
    if any(bad in command for bad in ("\n","\r",";", "&&","||","$",chr(96))):
        raise ValueError("Unsafe ExecStart")
    stamp=deadline.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    service=("[Unit]\nDescription=MNEBYDNS config restoration if uncommitted\n"
             "[Service]\nType=oneshot\nExecStart="+command+"\n")
    timer=("[Unit]\nDescription=Persistent MNEBYDNS rollback\n"
           "[Timer]\nOnCalendar="+stamp+"\nOnUnitInactiveSec=60s\nPersistent=true\nAccuracySec=1s\n"
           "Unit="+unit+".service\n[Install]\nWantedBy=timers.target\n")
    return service,timer

def commit_marker(root: Path, stage_sha: dict):
    """Persist commitment before disabling the rollback timer."""
    root=Path(root)
    fd=os.open(root/"COMMITTED",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        raw=(json.dumps(stage_sha,sort_keys=True)+"\n").encode()
        os.write(fd,raw)
        os.fsync(fd)
    finally:os.close(fd)
    dfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)

def original_template_parity(original: str,current: str) -> dict:
    """Text-semantic audit of all historical CoreDNS RR types (not DNS behavior)."""
    template=re.compile(r"(?ms)^[ \t]*template IN (A|AAAA|HTTPS|SVCB|CNAME) (\S+) \{(.*?)^[ \t]*\}")
    def parse(src):
        items=[]
        for m in template.finditer(src):
            body=m.group(3)
            vals=[]
            for word in ("match","answer","rcode"):
                lines=re.findall(r"(?m)^\s*"+word+r"\s+(.+)$",body)
                vals.append(tuple(x.strip() for x in lines))
            items.append((m.group(1),m.group(2),*vals))
        return items
    from collections import Counter
    old,new=parse(original),parse(current)
    if not old or not new:
        raise ValueError("Empty or unparseable CoreDNS template set")
    missing=Counter(old)-Counter(new)
    return {"historical_templates":len(old),"current_templates":len(new),
            "missing_or_changed_historical":sum(missing.values()),
            "historical_rr_types":sorted(set(x[0] for x in old)),
            "all_historical_rules_retained":not missing}
