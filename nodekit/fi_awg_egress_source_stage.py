#!/usr/bin/env python3
"""FI217 versioned production egress policy source staging only, no activation.

Upgrading the already installed code is a separate approved cutover.
"""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from fi_awg_policy_source_stage import APP, Blocked, checked_dir, checked_file, git_blob_id, live_guard

PIN="4a32a116f1e2c5c967806a4cdf0aee07f1a32985"
NAME="fi-awg-egress-signed-"+PIN[:12]
LOCK=Path("/run/lock/mnebyvpn-fi-awg-egress-source.lock")
SERVICES=(
    "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
    "mnebyvpn-nodekit-awg-egress@fi-test-01.service",
)

def require_dormant() -> None:
    live_guard()
    for service in SERVICES:
        state=subprocess.run(["/usr/bin/systemctl","show","-P","ActiveState",service],
                             capture_output=True,text=True,check=False,timeout=12)
        if state.returncode or state.stdout.strip() != "inactive":
            raise Blocked("watchdog or egress active")
    # This is only a source staging job; never edit units, network, or peers.

def verify(releases:Path)->None:
    path=releases/NAME
    checked_dir(path,private=True)
    if {item.name for item in path.iterdir()}!={"awg_egress.py"}:
        raise Blocked("unreviewed stage contents")
    if git_blob_id(checked_file(path/"awg_egress.py",private=True))!=PIN:
        raise Blocked("staged egress source drift")

def stage(source:Path,releases:Path)->str:
    checked_dir(releases,private=False)
    data=checked_file(source,private=True)
    if git_blob_id(data)!=PIN:
        raise Blocked("unreviewed egress source")
    destination=releases/NAME
    if destination.exists() or destination.is_symlink():
        verify(releases)
        return "ALREADY_PRESENT"
    with tempfile.TemporaryDirectory(prefix=".fi-egress-",dir=releases) as temporary:
        folder=Path(temporary)
        os.chmod(folder,0o700)
        target=folder/"awg_egress.py"
        with target.open("xb") as out:
            os.fchmod(out.fileno(),0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        directory=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        # No rename after malicious or partial stage.
        if git_blob_id(checked_file(target,private=True))!=PIN:
            raise Blocked("temporary source drift")
        os.rename(folder,destination)
    verify(releases)
    return "STAGED"

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("stage","verify"),required=True)
    p.add_argument("--source",type=Path)
    args=p.parse_args()
    try:
        if args.mode=="stage" and args.source is None:
            raise Blocked("source missing")
        require_dormant()
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if (st.st_uid!=0 or not stat.S_ISREG(st.st_mode) or
                stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1):
                raise Blocked("unsafe stage lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            releases=APP/"releases"
            checked_dir(releases,private=False)
            if args.mode=="stage":
                result=stage(args.source,releases)
            else:
                verify(releases);result="VERIFIED"
            require_dormant()
            print("FI_AWG_EGRESS_CODE="+result+";AWG_ACTIVE=false;CODE_SWITCHED=false;CUSTOMER_RELEASE_UNCHANGED=true")
            return 0
        finally:
            os.close(fd)
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        print("FI_AWG_EGRESS_CODE=BLOCKED;CODE_SWITCHED=false",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
