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

# Only fixed categories leave the node. Logs may contain peer material.
JOURNAL_MARKERS={
    "clock_rollback":("system utc rollback","system utc regressed","unsafe persisted offline clock"),
    "ledger_invalid":("invalid awg grant ledger","invalid awg entitlement ledger row","peer credential or client ip collision"),
    "peer_mismatch":("live awg allowed-ips differ","invalid live awg peer address table"),
    "config_drift":("staged awg config drift","amneziawg staged config changed"),
    "signed_approval":("signed production approval missing or invalid","productionadmissionerror"),
    "lifecycle_error":("nodekit_awg_lifecycle_error=",),
    "grant_error":("nodekit_awg_grants_error=",),
    "interface_missing":("cannot find device","no such device","awg interface is no longer managed"),
    "permission_error":("operation not permitted","permission denied"),
    "address_in_use":("address already in use","file exists"),
    "timeout":("timed out","timeout"),
    "dependency":("dependency failed","dependency job"),
    "exit_failure":("failed with result","control process exited"),
}

def journal_categories(raw:str)->list[str]:
    low=raw.lower()
    return [name for name,markers in JOURNAL_MARKERS.items()
            if any(marker in low for marker in markers)]

def failure_details(unit:str,prefix:str)->list[str]:
    if unit not in (FI_UNIT,FI_WATCHDOG):
        raise Blocked()
    result=[]
    try:
        raw=checked(["/usr/bin/systemctl","show","--property=Result",
                     "--property=ExecMainCode","--property=ExecMainStatus",unit],timeout=5)
        values=dict(line.split("=",1) for line in raw.splitlines() if "=" in line)
        known=("success","resources","protocol","timeout","exit-code","signal",
               "core-dump","watchdog","start-limit-hit","oom-kill","dependency","unknown")
        state=values.get("Result","unknown")
        result.append(prefix+"_RESULT="+(state if state in known else "unknown"))
        for prop in ("ExecMainCode","ExecMainStatus"):
            value=values.get(prop,"")
            result.append(prefix+"_"+prop.upper()+"="+
                          (value if re.fullmatch(r"[0-9]{1,3}",value) else "unknown"))
    except (Blocked,ValueError):
        result.append(prefix+"_SYSTEMD=unavailable")
    try:
        done=subprocess.run(["/usr/bin/journalctl","--unit",unit,"--since=48 hours ago",
                             "--lines=100","--no-pager","--output=cat"],
                            stdin=subprocess.DEVNULL,capture_output=True,text=True,
                            errors="replace",timeout=8,check=False)
        if done.returncode or len(done.stdout)>262144:
            raise Blocked()
        categories=journal_categories(done.stdout)
        result.append(prefix+"_JOURNAL="+(",".join(categories) if categories else "no_known_marker"))
    except (Blocked,OSError,subprocess.TimeoutExpired):
        result.append(prefix+"_JOURNAL=unavailable")
    return result

FI_EGRESS="mnebyvpn-nodekit-awg-egress@fi-test-01.service"

def stop_timeline(raw:str)->list[str]:
    # Journal message IDs and exact fixed phrases only; never emit raw messages.
    events=[]
    units={FI_UNIT:"awg",FI_WATCHDOG:"watchdog",FI_EGRESS:"egress"}
    for line in raw.splitlines():
        try:
            row=json.loads(line)
            if not isinstance(row,dict):continue
            unit=units.get(row.get("UNIT")) or units.get(row.get("_SYSTEMD_UNIT"))
            stamp=row.get("__REALTIME_TIMESTAMP","")
            msg=row.get("MESSAGE","")
            if not unit or not isinstance(stamp,str) or not re.fullmatch(r"[0-9]{16}",stamp) or not isinstance(msg,str):
                continue
            low=msg.lower()
            if "control process exited" in low:kind="control_exit"
            elif "failed with result" in low:kind="unit_failed"
            elif "stopping " in low:kind="stopping"
            elif "stopped " in low or "deactivated successfully" in low:kind="stopped"
            elif "starting " in low:kind="starting"
            elif "started " in low or "finished " in low:kind="started"
            elif "not a wireguard interface" in low or "not an amneziawg interface" in low:kind="interface_already_absent"
            elif "cannot find device" in low or "no such device" in low:kind="interface_missing"
            elif "nodekit_awg_grants_error=" in low:kind="grant_error"
            elif "nodekit_awg_lifecycle_error=" in low:kind="lifecycle_error"
            elif "nodekit_awg_egress_error=" in low:kind="egress_error"
            else:continue
            events.append((int(stamp),unit,kind))
        except (ValueError,TypeError):continue
    return [str(stamp//1000000)+":"+unit+":"+kind
            for stamp,unit,kind in sorted(set(events))[-30:]]

def stop_details()->list[str]:
    out=[]
    for unit,label in ((FI_UNIT,"AWG"),(FI_WATCHDOG,"WATCHDOG"),(FI_EGRESS,"EGRESS")):
        try:
            raw=checked(["/usr/bin/systemctl","show","--property=ExecStartPre",
                         "--property=ExecStart","--property=ExecStop","--property=ExecStopPost",unit],timeout=3)
            for line in raw.splitlines():
                key,sep,val=line.partition("=")
                if sep and key in ("ExecStartPre","ExecStart","ExecStop","ExecStopPost"):
                    statuses=re.findall(r"\\bstatus=([0-9]{1,3})(?:[/ ;}]|$)",val)
                    codes=re.findall(r"\\bcode=([a-z-]{1,16})(?:[ ;}]|$)",val)
                    allowed={"exited","killed","dumped"}
                    if statuses and len(statuses)==len(codes) and all(c in allowed for c in codes):
                        out.append("FI_AWG_PHASE_"+label+"_"+key.upper()+"="+
                                   ",".join(c+":"+v for c,v in zip(codes,statuses)))
        except (Blocked,ValueError):out.append("FI_AWG_PHASE_"+label+"=unavailable")
    try:
        done=subprocess.run(["/usr/bin/journalctl","--unit",FI_UNIT,"--unit",FI_WATCHDOG,
                             "--unit",FI_EGRESS,"--since=72 hours ago","--lines=300",
                             "--no-pager","--output=json"],stdin=subprocess.DEVNULL,
                            capture_output=True,text=True,errors="replace",timeout=5,check=False)
        if done.returncode or len(done.stdout)>1048576:raise Blocked()
        events=stop_timeline(done.stdout)
        out.extend("FI_AWG_TIMELINE="+event for event in events)
        if not events:out.append("FI_AWG_TIMELINE=no_known_event")
    except (Blocked,OSError,subprocess.TimeoutExpired):out.append("FI_AWG_TIMELINE=unavailable")
    return out

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
        if mode=="fi":
            for unit,prefix in ((FI_UNIT,"FI_AWG_FAILURE_SERVICE"),
                                (FI_WATCHDOG,"FI_AWG_FAILURE_WATCHDOG")):
                for line in failure_details(unit,prefix):
                    print(line,file=sys.stderr)
            for line in stop_details():
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
