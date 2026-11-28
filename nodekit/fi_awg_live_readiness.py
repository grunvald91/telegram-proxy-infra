#!/usr/bin/env python3
"""Read-only FI217 native AWG release inventory on RU188 or FI217.

No signers, credentials, peer keys, customer identities, network changes, or
release actions. The output is a bounded enumeration of readiness blockers.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib import request, error

RU_IP="188.120.254.223"
FI_IP="217.11.167.91"
FI_NODE="fi-test-01"
UNIT="mnebyvpn-awg-delivery.service"
FI_UNIT="mnebyvpn-nodekit-awg@fi-test-01.service"
FI_WATCHDOG="mnebyvpn-nodekit-awg-watchdog@fi-test-01.service"
DB_CONTAINER="mnebyvpn-stage-postgres"
WEB_ENV=Path("/opt/mnebyvpn/public/web.env")
FI_MANIFEST=Path("/var/lib/mnebyvpn-nodekit/fi-test-01/manifest.json")

class Blocked(Exception):
    pass

def checked(argv: list[str],timeout:int=12)->str:
    try:
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                              text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise Blocked()
    if result.returncode or len(result.stdout)>4096:
        raise Blocked()
    return result.stdout.strip()

def host(ip:str)->None:
    if os.geteuid()!=0:
        raise Blocked()
    values=checked(["/usr/sbin/ip","-o","-4","addr","show"])
    if not re.search(r"(?:^|\s)"+re.escape(ip)+r"/[0-9]{1,2}(?:\s|$)",values):
        raise Blocked()

def systemd_state(unit:str)->str:
    state=checked(["/usr/bin/systemctl","show","--property=ActiveState","--value",unit])
    if state not in ("active","inactive","failed","activating","deactivating"):
        raise Blocked()
    return state

def protected_text(path:Path,maximum:int)->str:
    if path.is_symlink():
        raise Blocked()
    meta=path.stat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or
        meta.st_mode & 0o022 or meta.st_nlink!=1 or
        not 1<=meta.st_size<=maximum):
        raise Blocked()
    return path.read_text(encoding="utf-8")

def web_configuration()->dict[str,str]:
    raw=protected_text(WEB_ENV,65536)
    options={}
    for line in raw.splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        key,value=line.split("=",1)
        if key in options:
            raise Blocked()
        options[key]=value.strip().strip("'\"")
    out={}
    for key in ("WEB_FI_AWG_REGISTRATION_ENABLED","WEB_FI_AWG_MATERIAL_ENABLED",
                "WEB_NETWORK_PROVISIONING_VERIFIED"):
        out[key]="yes" if options.get(key)=="yes" else "no"
    for key in ("WEB_FI_AWG_SERVER_PUBLIC_KEY","WEB_FI_AWG_HEADER_PROTECTION_KEY"):
        out[key]="present" if bool(re.fullmatch(r"[A-Za-z0-9+/]{43}=",options.get(key,""))) else "absent"
    return out

def ru()->dict[str,str]:
    host(RU_IP)
    worker=systemd_state(UNIT)
    sql=(
      "SELECT coalesce((SELECT enabled::text FROM public.vpn_release_flags "
      "WHERE feature='vpn_awg_clients'),'missing'),"
      "coalesce((SELECT state FROM public.vpn_awg_node_pools "
      "WHERE node_id='fi-test-01'),'missing'),"
      "coalesce((SELECT CASE WHEN state='verified' "
      "AND verified_at>clock_timestamp()-interval '1 hour' "
      "AND verified_at<=clock_timestamp()+interval '30 seconds' "
      "THEN 'fresh' ELSE 'not_fresh' END FROM public.vpn_awg_node_pools "
      "WHERE node_id='fi-test-01'),'missing'),"
      "coalesce((SELECT status FROM public.vpn_node_enrollment_inventory "
      "WHERE node_id='fi-test-01'),'missing'),"
      "(to_regclass('public.vpn_awg_device_requests') IS NOT NULL)::text"
    )
    value=checked(["/usr/bin/docker","exec",DB_CONTAINER,"psql","-X","-q",
                   "-A","-t","-F","|","-v","ON_ERROR_STOP=1",
                   "-U","mnebyvpn_stage","-d","mnebyvpn_stage","-c",sql],timeout=16)
    parts=value.split("|")
    if (len(parts)!=5 or parts[0] not in ("true","false","missing")
        or parts[1] not in ("staged","verified","missing")
        or parts[2] not in ("fresh","not_fresh","missing")
        or parts[3] not in ("enrolled","planned","approved","challenged","revoked","missing")
        or parts[4] not in ("true","false")):
        raise Blocked()
    result={
        "WORKER":worker,
        "RELEASE":parts[0],
        "POOL":parts[1],
        "POOL_PROOF":parts[2],
        "FI_ENROLLMENT":parts[3],
        "DEVICE_QUEUE":parts[4],
    }
    result.update(web_configuration())
    # This can be 404 while website registration is gated OFF.
    try:
        with request.urlopen("http://127.0.0.1:8792/awg/setup",timeout=5) as resp:
            code=resp.status
    except error.HTTPError as e:
        code=e.code
    except (OSError,ValueError):
        code=0
    result["WEB_AWG_PAGE"]="available" if code==200 else "not_published"
    return result

def fi()->dict[str,str]:
    host(FI_IP)
    data=json.loads(protected_text(FI_MANIFEST,16000))
    if not isinstance(data,dict) or data.get("node_id")!=FI_NODE or data.get("advertise_host")!="fi.mnebyvpn.site":
        raise Blocked()
    unit=systemd_state(FI_UNIT)
    watchdog=systemd_state(FI_WATCHDOG)
    try:
        awg=checked(["/usr/sbin/ip","link","show","dev","awg0"])
        iface="present" if awg else "absent"
    except Blocked:
        iface="absent"
    state=data.get("state")
    if state not in ("testing","active","enrolled"):
        state="unrecognized"
    return {
       "NODE_MANIFEST":state,
       "NODE_ACTIVATION":"yes" if data.get("activation_enabled") is True else "no",
       "NODE_REGISTRATION":"yes" if data.get("registration_enabled") is True else "no",
       "AWG_SERVICE":unit,
       "AWG_WATCHDOG":watchdog,
       "AWG_INTERFACE":iface,
    }

def diagnostic_fields(mode:str,report:dict[str,str])->list[str]:
    # The workflow captures stdout and collapses multiple fields into a
    # single readiness gate. Preserve that protocol; publish only fixed,
    # allowlisted component states on stderr, never raw command output.
    allowed={
        "ru":{"POOL":("staged","verified","missing"),
              "POOL_PROOF":("fresh","not_fresh","missing")},
        "fi":{"AWG_SERVICE":("active","inactive","failed","activating","deactivating"),
              "AWG_WATCHDOG":("active","inactive","failed","activating","deactivating"),
              "AWG_INTERFACE":("present","absent")},
    }
    return ["FI_AWG_DETAIL_"+key+"="+
            (report[key] if report.get(key) in values else "unknown")
            for key,values in allowed[mode].items()]

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=["ru","fi"],required=True)
    mode=parser.parse_args().mode
    try:
        report=ru() if mode=="ru" else fi()
        for key,value in sorted(report.items()):
            if not re.fullmatch(r"[A-Z_]{3,64}",key) or not re.fullmatch(r"[a-z_]{2,40}|true|false|yes|no",value):
                raise Blocked()
        for line in diagnostic_fields(mode,report):
            print(line,file=sys.stderr)
        print("FI_AWG_LIVE_AUDIT_"+mode.upper()+"="+
              ";".join(f"{key}:{value}" for key,value in sorted(report.items())))
        return 0
    except (Blocked,OSError,ValueError,TypeError,KeyError,UnicodeError,
            json.JSONDecodeError,subprocess.SubprocessError):
        print("FI_AWG_LIVE_AUDIT_"+mode.upper()+"=BLOCKED")
        return 2

if __name__=="__main__":
    sys.exit(main())
