#!/usr/bin/env python3
"""RU188 read-only subscription deployment inventory (no values or identifiers)."""
from __future__ import annotations
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

WEB=Path("/opt/mnebyvpn/public/web.env")
WORKER=Path("/root/mnebyvpn-controller/config/awg-delivery.env")
CURRENT="446c331249085adb6536e3d9913fb4b68abf6cd7"

def call(*argv: str) -> str:
    r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                     text=True,check=True,timeout=12)
    if len(r.stdout)>4096:raise ValueError("unexpected output size")
    return r.stdout.strip()

def keys(file:Path)->dict[str,str]:
    st=file.lstat()
    if not file.is_file() or file.is_symlink() or st.st_uid!=0 or st.st_mode&0o077:
        raise ValueError("untrusted root config")
    raw=file.read_bytes()
    if not 0<len(raw)<100000:raise ValueError("config size")
    result={}
    for line in raw.decode().splitlines():
        if not line or line.startswith("#"):continue
        name,sep,value=line.partition("=")
        if not sep or not re.fullmatch("[A-Z][A-Z0-9_]{2,80}",name) or name in result:
            raise ValueError("invalid config")
        result[name]=value
    return result

def main()->int:
    try:
        if os.geteuid()!=0 or "188.120.254.223" not in call("ip","-o","-4","addr","show"):
            raise ValueError("unexpected host")
        state=call("systemctl","show","-p","ActiveState","--value","mnebyvpn-awg-delivery.service")
        wd=call("systemctl","show","-p","WorkingDirectory","--value","mnebyvpn-awg-delivery.service")
        if state not in ("active","inactive","failed"):
            raise ValueError("unknown worker state")
        release=Path(wd)
        if release.parent!=Path("/opt/mnebyvpn-controller/awg-worker-releases"):
            raise ValueError("unexpected worker base")
        web=keys(WEB)
        worker=keys(WORKER)
        site=call("docker","inspect","-f","{{.State.Running}}","mnebyvpn-public-web")
        print("FI_AWG_SUB_WORKER_ACTIVE="+("true" if state=="active" else "false"))
        print("FI_AWG_SUB_WORKER_SOURCE="+("PINNED_SIX_MODULE" if release.name==CURRENT else "OTHER_REVIEW_REQUIRED"))
        print("FI_AWG_SUB_OLD_DEPENDENCIES="+
              ("present" if (release/"node_modules/pg/package.json").is_file() else "absent"))
        print("FI_AWG_SUB_OLD_PG_SYMLINK="+
              ("yes" if (release/"node_modules").is_symlink() else "no"))
        print("FI_AWG_SUB_WEB_RUNNING="+site)
        print("FI_AWG_SUB_FI_MATERIAL="+web.get("WEB_FI_AWG_MATERIAL_ENABLED","missing"))
        print("FI_AWG_SUB_WEB_MIXED_FEATURE="+web.get("WEB_FI_AWG_IN_SUBSCRIPTION_ENABLED","missing"))
        print("FI_AWG_SUB_WEB_SECRET="+("present" if web.get("AWG_INCY_SUBSCRIPTION_SEED") else "missing"))
        print("FI_AWG_SUB_WORKER_SECRET="+("present" if worker.get("AWG_INCY_SUBSCRIPTION_SEED") else "missing"))
        print("FI_AWG_SUB_WEB_SHA_PRESENT="+
              ("yes" if (Path("/opt/mnebyvpn/public/active_sha")).is_file() else "no"))
        return 0
    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
        print("FI_AWG_SUB_INVENTORY=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
