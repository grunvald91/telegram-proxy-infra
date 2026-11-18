#!/usr/bin/env python3
"""One-off signed AWG grant/revoke canary on isolated FI.

Controller private key remains on the ephemeral runner. Node stores only the
temporary Ed25519 public key, and an independent systemd timer destroys the
testing ledger and stops AWG even if SSH or the runner dies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

from awg_lifecycle import active_unit, enabled_unit, unit_name, validate
from install_components import node_ready, safe_manifest

ROOT=Path("/var/lib/mnebyvpn-nodekit")
NODE="fi-test-01"
HOST="fi.mnebyvpn.site"
UID="00000000-0000-4000-8000-000000000001"
ROOT_STATE=Path("/run/nodekit-fi-awg-signed-canary.json")
PUB=ROOT/NODE/"controller-access.spki"
LEDGER=ROOT/NODE/"amneziawg"/"peer-grants.json"
LEDGER_LOCK=ROOT/NODE/"amneziawg"/"peer-grants.lock"
TIMER="nodekit-fi-awg-signed-guard"
AWG=unit_name(NODE)
WATCHDOG="mnebyvpn-nodekit-awg-watchdog@"+NODE+".service"
EGRESS="mnebyvpn-nodekit-awg-egress@"+NODE+".service"
PREFIX=bytes.fromhex("302a300506032b6570032100")


class CanaryError(ValueError):
    pass


def call(*argv,check=True,timeout=15):
    return subprocess.run(list(argv),check=check,capture_output=True,text=True,timeout=timeout)


def stat_file(path, private=True, max_bytes=1200):
    if path.is_symlink() or not path.is_file():
        raise CanaryError("Missing protected test input")
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or (
            st.st_mode & (0o077 if private else 0o022)) or
            st.st_size<=0 or st.st_size>max_bytes:
        raise CanaryError("Unsafe test file owner, mode or length")
    return path.read_bytes()


def read_state():
    if not ROOT_STATE.exists() and not ROOT_STATE.is_symlink():
        return None
    value=json.loads(stat_file(ROOT_STATE))
    if (not isinstance(value,dict) or
            set(value)!={"pub_sha256","expires"} or
            type(value["expires"]) not in (int,float) or
            not re.fullmatch("[a-f0-9]{64}",value["pub_sha256"])):
        raise CanaryError("Untrusted test session manifest")
    return value


def approved_node():
    if os.geteuid()!=0:
        raise CanaryError("Root-only canary")
    node=node_ready(ROOT,NODE)
    validate(node)
    manifest=safe_manifest(node/"manifest.json")
    if (manifest.get("advertise_host")!=HOST or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False):
        raise CanaryError("Only isolated unpublished FI node permitted")
    for unit in (AWG,WATCHDOG,EGRESS):
        if active_unit(unit) or enabled_unit(unit):
            raise CanaryError("AWG subscriber service already active or enabled")
    if Path("/sys/class/net/awg0").exists():
        raise CanaryError("Live AWG interface already exists")
    if Path("/run/nodekit-awg-fi-egress.json").exists():
        raise CanaryError("Internet egress must remain off")
    return node


def prepare(public_path:Path, seconds:int)->dict:
    if seconds<60 or seconds>110:
        raise CanaryError("Canary TTL must be between 60 and 110 seconds")
    node=approved_node()
    if (ROOT_STATE.exists() or ROOT_STATE.is_symlink() or
            PUB.exists() or PUB.is_symlink() or
            LEDGER.exists() or LEDGER.is_symlink() or
            LEDGER_LOCK.exists() or LEDGER_LOCK.is_symlink()):
        raise CanaryError("Never overwrite a controller key or existing grants")
    parent=public_path.parent
    if (parent.is_symlink() or parent.stat().st_uid!=0 or
            parent.stat().st_mode & 0o077):
        raise CanaryError("Public staging directory must be root-only")
    public=stat_file(public_path,private=False,max_bytes=100)
    if len(public)!=44 or not public.startswith(PREFIX):
        raise CanaryError("Invalid test Ed25519 public key")
    # Root-only state enables fail-safe cleanup but is not a client grant.
    sha=hashlib.sha256(public).hexdigest()
    fd=os.open(ROOT_STATE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"w") as out:
            json.dump({"pub_sha256":sha,"expires":time.time()+seconds},out)
            out.flush();os.fsync(out.fileno())
        # Timer uses this root-owned script in the temporary SSH directory.
        # A failed/disconnected runner will leave the directory for the timer.
        call("systemd-run","--unit="+TIMER,"--on-active="+str(seconds)+"s",
             "/usr/bin/python3",str(Path(__file__).resolve()),
             "--mode","cleanup")
        public_fd=os.open(PUB,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(public_fd,"wb") as out:
            out.write(public);out.flush();os.fsync(out.fileno())
    except BaseException:
        cleanup()
        raise
    return {"prepared":True,"test_controller_public_only":True,
            "ttl_seconds":seconds,"subscribers_enabled":False}


def cleanup()->dict:
    if os.geteuid()!=0:
        raise CanaryError("Root required")
    session=read_state()
    if session is None:
        return {"clean":True,"already_clean":True}
    # Stop services even if the ledger is corrupt; never leave test access up.
    call("systemctl","stop",WATCHDOG,check=False,timeout=35)
    call("systemctl","stop",AWG,check=False,timeout=35)
    if active_unit(WATCHDOG) or active_unit(AWG):
        raise CanaryError("AWG did not stop; emergency operator action required")
    if active_unit(EGRESS):
        raise CanaryError("Unrelated egress active; never erase shared controller")
    if LEDGER.exists() or LEDGER.is_symlink():
        ledger=json.loads(stat_file(LEDGER,max_bytes=50000))
        if (not isinstance(ledger,dict) or
                ledger.get("node_id")!=NODE or
                set(ledger.get("grants",{}))-{UID}):
            raise CanaryError("Test ledger has unknown clients: do not delete")
    if PUB.exists() or PUB.is_symlink():
        if hashlib.sha256(stat_file(PUB,max_bytes=100)).hexdigest()!=session["pub_sha256"]:
            raise CanaryError("Pinned controller key changed; do not delete")
        PUB.unlink()
    LEDGER.unlink(missing_ok=True)
    LEDGER_LOCK.unlink(missing_ok=True)
    ROOT_STATE.unlink(missing_ok=True)
    call("systemctl","stop",TIMER+".timer",check=False)
    return {"clean":True,"awg_stopped":True,
            "temporary_controller_public_removed":True,
            "test_ledger_removed":True}


def inspect()->dict:
    session=read_state()
    peers=call("/opt/mnebyvpn-amneziawg/awg","show","awg0","allowed-ips",
               check=False)
    return {"test_armed":session is not None,"awg_active":active_unit(AWG),
            "watchdog_active":active_unit(WATCHDOG),
            "egress_active":active_unit(EGRESS),
            "one_test_client": bool(session and UID in
                    json.loads(LEDGER.read_text()).get("grants",{})
                    if LEDGER.exists() else False),
            "peer_count":len(peers.stdout.splitlines())
                    if peers.returncode==0 else None}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("prepare","cleanup","inspect"),required=True)
    p.add_argument("--controller-public",type=Path)
    p.add_argument("--ttl",type=int,default=105)
    args=p.parse_args()
    try:
        if args.mode=="prepare":
            if not args.controller_public:raise CanaryError("Test public key required")
            result=prepare(args.controller_public,args.ttl)
        elif args.mode=="cleanup":result=cleanup()
        else:result=inspect()
        print(json.dumps(result,sort_keys=True))
        return 0
    except (OSError,ValueError,subprocess.SubprocessError,TypeError) as exc:
        print("AWG_SIGNED_CANARY_ERROR="+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
