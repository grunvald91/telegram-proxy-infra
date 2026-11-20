#!/usr/bin/env python3
"""RU188 read-only subscription deployment inventory (no values or identifiers)."""
from __future__ import annotations
import os
import hmac
from pathlib import Path
import re
import socket
import subprocess
import sys

WEB=Path("/opt/mnebyvpn/public/web.env")
WORKER=Path("/root/mnebyvpn-controller/config/awg-delivery.env")
CURRENT="eec5b86c62b6c58bdbda8735c7e75fd9f38fd859"

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

def db_status()->dict[str,str]:
    # Exact fixed aggregate-only SQL: no bearer, peer, customer id,
    # account data, seed or profile material may reach Action logs.
    sql="""
SELECT
 (SELECT count(*) FROM public.entitlements e
  JOIN public.provisioning_state v ON v.entitlement_id=e.id
  WHERE e.product='vpn' AND e.state='ACTIVE'
    AND e.expires_at>clock_timestamp()
    AND v.adapter='vpn' AND v.applied_revision=e.revision
    AND v.last_observed_at IS NOT NULL),
 (SELECT count(*) FROM public.vpn_awg_device_requests
  WHERE node_id='fi-test-01'),
 (SELECT count(*) FROM public.vpn_awg_device_requests
  WHERE node_id='fi-test-01' AND state IN ('queued','processing')),
 (SELECT count(*) FROM public.vpn_awg_peer_allocations
  WHERE node_id='fi-test-01' AND state='applied'),
 (SELECT count(*) FROM public.vpn_awg_peer_allocations a
  JOIN public.vpn_awg_command_outbox o
    ON o.node_id=a.node_id AND o.entitlement_id=a.entitlement_id
    AND o.revision=a.revision AND o.op='grant'
  JOIN public.entitlements e ON e.id=a.entitlement_id
  WHERE a.node_id='fi-test-01' AND a.state='applied'
    AND o.state='applied'
    AND o.node_receipt_sha256 ~ '^[a-f0-9]{64}    try:
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
        print("FI_AWG_SUB_WORKER_SOURCE="+("APPROVED_20261120" if release.name==CURRENT else "OTHER_REVIEW_REQUIRED"))
        print("FI_AWG_SUB_OLD_DEPENDENCIES="+
              ("present" if (release/"node_modules/pg/package.json").is_file() else "absent"))
        print("FI_AWG_SUB_OLD_PG_SYMLINK="+
              ("yes" if (release/"node_modules").is_symlink() else "no"))
        print("FI_AWG_SUB_WEB_RUNNING="+site)
        print("FI_AWG_SUB_FI_MATERIAL="+web.get("WEB_FI_AWG_MATERIAL_ENABLED","missing"))
        print("FI_AWG_SUB_WEB_MIXED_FEATURE="+web.get("WEB_FI_AWG_IN_SUBSCRIPTION_ENABLED","missing"))
        print("FI_AWG_SUB_WEB_SECRET="+("present" if web.get("AWG_INCY_SUBSCRIPTION_SEED") else "missing"))
        print("FI_AWG_SUB_WORKER_SECRET="+("present" if worker.get("AWG_INCY_SUBSCRIPTION_SEED") else "missing"))
        print("FI_AWG_SUB_SEED_MATCH="+(
            "true" if web.get("AWG_INCY_SUBSCRIPTION_SEED") and
            hmac.compare_digest(web["AWG_INCY_SUBSCRIPTION_SEED"],
                                worker.get("AWG_INCY_SUBSCRIPTION_SEED",""))
            else "false"))
        for key,value in db_status().items():
            print("FI_AWG_SUB_"+key+"="+value)
        print("FI_AWG_SUB_WEB_SHA_PRESENT="+
              ("yes" if (Path("/opt/mnebyvpn/public/active_sha")).is_file() else "no"))
        return 0
    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
        print("FI_AWG_SUB_INVENTORY=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())

    AND o.command_sha256=a.last_command_sha256
    AND o.billing_revision=e.revision
    AND e.product='vpn' AND e.state='ACTIVE'
    AND e.expires_at>clock_timestamp()),
 (SELECT CASE WHEN state='verified'
    AND verified_at>clock_timestamp()-interval '1 hour'
    AND verified_at<=clock_timestamp()+interval '30 seconds'
    THEN 'FRESH' ELSE 'STALE' END
  FROM public.vpn_awg_node_pools WHERE node_id='fi-test-01'),
 (SELECT enabled::text FROM public.vpn_release_flags
  WHERE feature='vpn_awg_clients');
"""
    out=call("docker","exec","mnebyvpn-stage-postgres","psql","-X","-q",
             "-A","-t","-v","ON_ERROR_STOP=1","-U","mnebyvpn_stage",
             "-d","mnebyvpn_stage","-c",sql)
    pieces=out.split("|")
    if len(pieces)!=7 or any(not x.isdecimal() for x in pieces[:5]):
        raise ValueError("unexpected aggregated subscription query")
    if pieces[5] not in ("FRESH","STALE") or pieces[6] not in ("true","false"):
        raise ValueError("missing canonical FI node state")
    labels=("ACTIVE_VPN_ENTITLEMENTS","FI_DEVICE_REQUESTS","FI_REQUESTS_PENDING",
            "FI_PEERS_APPLIED","FI_SIGNED_ACKS")
    result={name:value for name,value in zip(labels,pieces[:5])}
    result["FI_POOL_PROOF"]=pieces[5]
    result["FI_CUSTOMER_RELEASE"]=pieces[6]
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
