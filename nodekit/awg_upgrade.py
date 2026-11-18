#!/usr/bin/env python3
"""Audit-bound inactive Nodekit AWG code migration.

Atomic, reversible replacement of TWO reviewed, root-only Python modules.
Does not create users, change systemd units/firewall, or restart any service.
An unexpected installed source is a hard failure, not a blind overwrite.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

from awg_lifecycle import active_unit, enabled_unit, unit_name, validate as validate_awg
from install_components import node_ready

ROOT=Path("/var/lib/mnebyvpn-nodekit")
APP=Path("/opt/mnebyvpn-nodekit")
# Git *blob* hashes of the previously reviewed code already installed on FI.
# Changing this allowlist requires a new audited PR.
BASELINE={
    "awg_peer_grants.py":{
        "4a9b336a072157e18b41a25ee63b96ea50ea8b50",
        "dedd8543f6eb9d630b62cff908b6c7ade17ff6d7",
    },
    "awg_egress.py":{
        "e9f094f0ae15d36732169a5bd18da72a2576dcf1",
        "5d275e58690cb79e8143da821b2787050c123633",
    },
}

class UpgradeError(ValueError):
    pass

def blob_sha1(contents:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(contents)).encode()+b"\0"+contents).hexdigest()

def safe_bytes(path:Path,*,require_private=True)->bytes:
    if path.is_symlink() or not path.is_file():
        raise UpgradeError("Nodekit source is missing or symlinked")
    st=path.stat()
    if (st.st_uid!=0 or st.st_mode & (0o077 if require_private else 0o022)
        or not stat.S_ISREG(st.st_mode) or st.st_size>150000 or st.st_size<=0):
        raise UpgradeError("Unsafe root-owned Nodekit source")
    return path.read_bytes()

def services_idle(node_id:str)->None:
    names=[
        unit_name(node_id),
        "mnebyvpn-nodekit-awg-watchdog@"+node_id+".service",
        "mnebyvpn-nodekit-awg-egress@"+node_id+".service",
    ]
    for name in names:
        if active_unit(name) or enabled_unit(name):
            raise UpgradeError("AWG service active or enabled; upgrade refused")
    if (Path("/sys/class/net/awg0").exists() or
        Path("/run/nodekit-awg-fi-egress.json").exists() or
        Path("/run/nodekit-fi-awg-external.json").exists()):
        raise UpgradeError("AWG interface or network lease still active")

def prepare(node:Path,source_dir:Path):
    if node.name!="fi-test-01" or os.geteuid()!=0:
        raise UpgradeError("This migration only approves isolated FI")
    validate_awg(node)
    services_idle(node.name)
    if (source_dir.is_symlink() or not source_dir.is_dir() or
        source_dir.stat().st_uid!=0 or source_dir.stat().st_mode & 0o077):
        raise UpgradeError("Untrusted source directory")
    if APP.is_symlink() or not APP.is_dir() or APP.stat().st_uid!=0:
        raise UpgradeError("Untrusted installed code directory")
    current={}
    for name,old_sha in BASELINE.items():
        installed=APP/name
        original=safe_bytes(installed)
        # SCP may create mode 0644 files inside the root-only 0700 staging
        # directory. Owner and non-writability are the relevant checks.
        desired=safe_bytes(source_dir/name,require_private=False)
        # Refuse to replace a working service with syntactically invalid code.
        ast.parse(desired.decode("utf8"),filename=name)
        existing=blob_sha1(original)
        target=blob_sha1(desired)
        if existing not in old_sha and existing!=target:
            raise UpgradeError("Installed AWG code differs from approved baseline")
        # Never downgrade if already deployed, and never rewrite identical code.
        current[name]={"old":existing,"new":target,
                       "needed":existing!=target,"old_source":original,"new_source":desired}
    # Any peer ledger must still be empty. Never change code under clients.
    ledger=node/"amneziawg"/"peer-grants.json"
    if ledger.exists() or ledger.is_symlink():
        from awg_peer_grants import validate_state,protected_file
        state=validate_state(json.loads(protected_file(ledger)),node.name)
        if state["grants"]:
            raise UpgradeError("Existing customer peer ledger cannot be upgraded")
    return current

def atomic_bytes(path:Path,payload:bytes,mode=0o600)->None:
    fd,tmp=tempfile.mkstemp(prefix=".nodekit-code-swap-",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"wb") as handle:
            handle.write(payload);handle.flush();os.fsync(handle.fileno())
        os.replace(tmp,path)
    finally:Path(tmp).unlink(missing_ok=True)

def execute(node:Path,source_dir:Path):
    planned=prepare(node,source_dir)
    changed=[]
    try:
        for name,entry in planned.items():
            if not entry["needed"]:continue
            services_idle(node.name)
            atomic_bytes(APP/name,entry["new_source"])
            changed.append(name)
            if blob_sha1(safe_bytes(APP/name))!=entry["new"]:
                raise UpgradeError("Post-install code hash mismatch")
        # Checking the installed source cannot accidentally open a network
        # port; no systemd unit or runtime configuration is modified.
        return {"node_id":node.name,
                "changed":changed,
                "installed":{k:{"blob_sha1":v["new"]} for k,v in planned.items()},
                "services_started":False,"subscriber_access_enabled":False}
    except BaseException:
        for name in reversed(changed):
            atomic_bytes(APP/name,planned[name]["old_source"])
        raise

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id",required=True)
    p.add_argument("--source-dir",type=Path,required=True)
    p.add_argument("--stage-root",type=Path,default=ROOT)
    args=p.parse_args()
    try:
        node=node_ready(args.stage_root,args.node_id)
        print(json.dumps(execute(node,args.source_dir),sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        print("AWG_INACTIVE_UPGRADE_ERROR="+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
