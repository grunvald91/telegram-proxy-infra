#!/usr/bin/env python3
"""One-peer live check of staged NFQUEUE210 rule generator, with timed rollback.

Requires staged generator and *no* default opt-in peer. Rebuilds only the
telegram_nfqws table, never restarts Telegram or touches DNS/Nginx/WireGuard.
"""
from __future__ import annotations
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

GEN=Path("/usr/local/sbin/telegram-nfqws-rules")
CONF=Path("/etc/mnebydns/telegram-synack-canary-ipv4")
TARGET_SHA="8beeffbe10e7da097e10bde4b1ef568219d52c2f1c04b189e71602069de9ec3f"
TAG="MNEBYDNS_SYNACK_CANARY_PEER_V1"
LOCK="/run/lock/mnebydns-nfqws-guard-install.lock"
TAG_OLD="MNEBY_IG_SYNACK_AB_"

def run(argv, *,env=None,timeout=15,check=True):
    p=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError("Command failed: "+argv[0]+": "+p.stderr.strip()[:400])
    return p

def chain():
    return run(["nft","-a","list","chain","inet","telegram_nfqws","post"]).stdout

def q210_ok(txt):
    q=[line for line in txt.splitlines() if "tcp sport 443" in line and re.search(r"\bto\s+210\b",line)]
    return len(q)==1 and "bypass" in q[0]

def tagged(txt):
    hits=[]
    for line in txt.splitlines():
        if TAG not in line:
            continue
        match=re.search(r"# handle (\d+)\s*$",line)
        if match: hits.append((int(match.group(1)),line))
    return hits

def clean_guard():
    found=tagged(chain())
    if len(found)>1:
        raise RuntimeError("Multiple guarded rules — unsafe to delete blindly")
    for handle,_ in found:
        run(["nft","delete","rule","inet","telegram_nfqws","post","handle",str(handle)])
    return len(found)

def watchdog_script(path:Path,peerfile:Path):
    code='''#!/usr/bin/env python3
import pathlib,re,subprocess
tag="MNEBYDNS_SYNACK_CANARY_PEER_V1"
conf=pathlib.Path(%r)
path=pathlib.Path(%r)
try:
    p=subprocess.run(["nft","-a","list","chain","inet","telegram_nfqws","post"],capture_output=True,text=True,timeout=10)
    if p.returncode == 0:
        for line in p.stdout.splitlines():
            if tag not in line: continue
            m=re.search(r"# handle (\\d+)\\s*$",line)
            if m:
                subprocess.run(["nft","delete","rule","inet","telegram_nfqws","post","handle",m.group(1)],check=True,timeout=12)
                print("generator_canary_watchdog=GUARD_REMOVED",flush=True)
        if not any("to 210" in line and "tcp sport 443" in line for line in p.stdout.splitlines()):
            subprocess.run(["/usr/local/sbin/telegram-nfqws-rules","apply"],check=True,timeout=15)
            print("generator_canary_watchdog=QUEUE_REBUILT",flush=True)
finally:
    conf.unlink(missing_ok=True)
    path.unlink(missing_ok=True)
''' % (str(peerfile),str(path))
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
    with os.fdopen(fd,"w") as f:
        f.write(code);f.flush();os.fsync(f.fileno())

def main():
    if os.geteuid()!=0 or len(sys.argv)!=3:
        raise SystemExit("Usage: python3 - PEER_PUBLIC_IPV4 RUN_ID")
    peer=ipaddress.IPv4Address(sys.argv[1])
    if not peer.is_global or str(peer)=="188.120.254.223":
        raise ValueError("Invalid test public peer")
    runid=sys.argv[2]
    if not re.fullmatch(r"\d{8,18}",runid):
        raise ValueError("Invalid run ID")
    if not GEN.is_file() or hashlib.sha256(GEN.read_bytes()).hexdigest()!=TARGET_SHA:
        raise RuntimeError("Staged generator SHA mismatch")
    if CONF.exists() or CONF.is_symlink():
        raise RuntimeError("A persistent client allow file is present: abort")
    if run(["systemctl","is-active","--quiet","telegram-nfqws.service"],check=False).returncode!=0:
        raise RuntimeError("Existing Telegram service inactive")
    peerfile=Path("/run/mnebydns-synack-peer-"+runid)
    helper=Path("/run/mnebydns-synack-rollback-"+runid+".py")
    unit="mneby-nfqws-guard-"+runid
    applied=False
    with open(LOCK,"a") as l:
        fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB)
        before=chain()
        if not q210_ok(before) or TAG in before or TAG_OLD in before:
            raise RuntimeError("Unexpected existing rules; refuse changes")
        if peerfile.exists() or helper.exists():
            raise RuntimeError("A previous test run left files")
        if run(["systemctl","is-active","--quiet",unit+".timer"],check=False).returncode==0:
            raise RuntimeError("Rollback timer already active")
        fd=os.open(peerfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"w") as f:
            f.write(str(peer)+"\n");f.flush();os.fsync(f.fileno())
        try:
            watchdog_script(helper,peerfile)
            run(["systemd-run","--quiet","--collect","--unit",unit,"--on-active=85s","/usr/bin/python3",str(helper)])
            if run(["systemctl","is-active","--quiet",unit+".timer"],check=False).returncode:
                raise RuntimeError("Independent rollback timer not active")
            env=os.environ.copy()
            env["MNEBYDNS_SYNACK_CANARY_FILE"]=str(peerfile)
            applied=True  # even a partially successful apply must be cleaned up
            run([str(GEN),"apply"],env=env,timeout=20)
            current=chain()
            matches=tagged(current)
            if len(matches)!=1 or not q210_ok(current):
                raise RuntimeError("Expected guarded rule and original queue 210")
            if not current.index(matches[0][1]) < current.index("to 210"):
                raise RuntimeError("Guard is not before queue210")
            if run(["systemctl","is-active","--quiet","telegram-nfqws.service"],check=False).returncode:
                raise RuntimeError("Telegram service no longer active")
            print("generator_canary=READY",flush=True)
            print("generator_canary_scope=one_peer_ipv4_synack_only",flush=True)
            print("generator_canary_independent_rollback=ARMED",flush=True)
            time.sleep(40)
            final=chain()
            active=tagged(final)
            if len(active)==1:
                m=re.search(r"counter packets (\d+) bytes (\d+)",active[0][1])
                print("generator_canary_packet_count="+(m.group(1) if m else "UNKNOWN"),flush=True)
        finally:
            try:
                if applied:
                    cleaned=clean_guard()
                    print("generator_canary_cleanup="+("REMOVED" if cleaned else "ALREADY_REMOVED"),flush=True)
                else:
                    print("generator_canary_cleanup=NOT_INSTALLED",flush=True)
                if not q210_ok(chain()):
                    # Trigger the known-good generator without any opt-in.
                    run([str(GEN),"apply"],timeout=20)
                    print("generator_canary_queue_rebuilt=true",flush=True)
                if TAG in chain():
                    raise RuntimeError("Canary rule remains after cleanup")
            finally:
                peerfile.unlink(missing_ok=True)
                # The watchdog remains scheduled and will re-check the chain.
    print("generator_canary=FINISHED_ORIGINAL_QUEUE_RETAINED",flush=True)

if __name__=="__main__":
    main()
