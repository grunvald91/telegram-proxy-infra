#!/usr/bin/env python3
"""Stage opt-in nft SYN-ACK guard generator on RU; NO firewall/service mutations.

Immutable baseline SHA must match the live root-owned executable.
Atomic install with an on-server backup and rollback-on-failure.
The opt-in allow-IP file MUST NOT exist at staging time.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import fcntl

TARGET=Path("/usr/local/sbin/telegram-nfqws-rules")
ALLOW=Path("/etc/mnebydns/telegram-synack-canary-ipv4")
BACKUPS=Path("/var/backups/mnebydns-nfqws")
LOCK=Path("/run/lock/mnebydns-nfqws-guard-install.lock")
TAG="MNEBYDNS_SYNACK_CANARY_PEER_V1"
TABLE=["nft","-a","list","chain","inet","telegram_nfqws","post"]

def digest(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def exec_read(args):
    v=subprocess.run(args,capture_output=True,text=True,timeout=12)
    if v.returncode:
        raise RuntimeError("Read-only preflight command failed: "+args[0])
    return v.stdout

def live_state()->dict:
    chain=exec_read(TABLE)
    q=[x for x in chain.splitlines() if "tcp sport 443" in x and re.search(r"\bto\s+210\b",x)]
    if len(q)!=1 or "bypass" not in q[0] or TAG in chain or "MNEBY_IG_SYNACK_AB_" in chain:
        raise RuntimeError("Live queue210 rule or test markers differ: fail closed")
    worker=subprocess.run(["systemctl","is-active","--quiet","telegram-nfqws.service"],timeout=12).returncode==0
    listeners=exec_read(["ss","-H","-lnt"])
    https=any(re.search(r":443\s",row) for row in listeners.splitlines())
    qfile=Path("/proc/net/netfilter/nfnetlink_queue")
    bound=qfile.is_file() and any(row.split() and row.split()[0]=="210" for row in qfile.read_text().splitlines())
    if not all((worker,https,bound)):
        raise RuntimeError("Telegram worker, TCP443 listener or NFQUEUE210 missing")
    # Rule counters can change, so compare only the observed queue expression.
    return {"queue_rule":re.sub(r"counter packets \d+ bytes \d+","counter",re.sub(r"\s+# handle \d+$","",q[0])).strip(),
            "worker":worker,"https":https,"bound":bound}

def atomic_file(target:Path, data:bytes, mode:int):
    fd,name=tempfile.mkstemp(prefix=".mnebydns-guard-",dir=str(target.parent))
    try:
        with os.fdopen(fd,"wb") as file:
            file.write(data);file.flush();os.fsync(file.fileno())
        os.chmod(name,mode)
        os.chown(name,0,0)
        os.replace(name,target)
        dirfd=os.open(target.parent,os.O_RDONLY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:
        if os.path.lexists(name):os.unlink(name)

def stage(candidate:Path, base_sha:str, candidate_sha:str, runid:str):
    if not re.fullmatch(r"\d{8,18}",runid):raise ValueError("Invalid run id")
    if not re.fullmatch("[0-9a-f]{64}",base_sha+"" ) or not re.fullmatch("[0-9a-f]{64}",candidate_sha):
        raise ValueError("Invalid SHA256")
    if os.geteuid()!=0:raise RuntimeError("Root required")
    if ALLOW.exists() or ALLOW.is_symlink():
        raise RuntimeError("Opt-in peer already configured; refuse staging")
    if TARGET.is_symlink() or not TARGET.is_file() or TARGET.stat().st_uid!=0:
        raise RuntimeError("Unexpected live generator ownership/type")
    with open(LOCK,"a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        original=TARGET.read_bytes()
        if digest(original)!=base_sha:
            raise RuntimeError("Live generator SHA mismatch; no changes")
        current=live_state()
        candidate_bytes=candidate.read_bytes()
        if digest(candidate_bytes)!=candidate_sha:
            raise RuntimeError("Candidate SHA mismatch; no changes")
        src=candidate_bytes.decode("utf-8")
        if src.count(TAG)!=1 or src.count("queue num \"$QUEUE\" bypass comment telegram-nfqws")!=1:
            raise RuntimeError("Candidate missing exact opt-in guard and original queue210 rule")
        if "SYNACK_FILE=" not in src:
            raise RuntimeError("Candidate opt-in file selection missing")
        synt=subprocess.run(["sh","-n"],input=src,text=True,capture_output=True,timeout=10)
        if synt.returncode:raise RuntimeError("Candidate shell syntax invalid")
        BACKUPS.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chmod(BACKUPS,0o700)
        backup=BACKUPS/("telegram-nfqws-rules."+runid+".bak")
        fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,"wb") as file:
                file.write(original);file.flush();os.fsync(file.fileno())
        except BaseException:
            backup.unlink(missing_ok=True)
            raise
        mode=stat.S_IMODE(TARGET.stat().st_mode)
        changed=False
        try:
            atomic_file(TARGET,candidate_bytes,mode)
            changed=True
            if digest(TARGET.read_bytes())!=candidate_sha:
                raise RuntimeError("Post-install generator digest mismatch")
            if ALLOW.exists() or ALLOW.is_symlink():
                raise RuntimeError("Opt-in peer appeared unexpectedly")
            if live_state()!=current:
                raise RuntimeError("Live queue210/worker/HTTPS state changed during stage")
        except BaseException:
            if changed:atomic_file(TARGET,original,mode)
            print("nfqws_stage=ROLLED_BACK_AFTER_ERROR",flush=True)
            raise
        print("nfqws_stage=INSTALLED_GUARD_OPT_IN_DISABLED",flush=True)
        print("nfqws_original_sha256="+base_sha,flush=True)
        print("nfqws_guarded_sha256="+candidate_sha,flush=True)
        print("nfqws_live_queue210_unchanged=true",flush=True)
        print("nfqws_telegram_service_still_active=true",flush=True)
        print("nfqws_https_listener_still_present=true",flush=True)
        print("nfqws_backup_basename="+backup.name,flush=True)

def main():
    if len(sys.argv)!=5:
        raise SystemExit("Usage: python3 - CANDIDATE_PATH LIVE_BASE_SHA CANDIDATE_SHA RUN_ID")
    try:stage(Path(sys.argv[1]),sys.argv[2],sys.argv[3],sys.argv[4])
    finally:
        # The candidate is temporary in /run; cleanup is safe even on failure.
        p=Path(sys.argv[1])
        if p.parent==Path("/run") and p.name.startswith("mnebydns-nfqws-guard-"):
            p.unlink(missing_ok=True)

if __name__=="__main__":
    main()
