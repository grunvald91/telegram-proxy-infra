#!/usr/bin/env python3
"""RU188 read-only native FI217 subscription inventory; never print account secrets."""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

WEB=Path("/opt/mnebyvpn/public/web.env")
WORKER=Path("/root/mnebyvpn-controller/config/awg-delivery.env")
CURRENT="eec5b86c62b6c58bdbda8735c7e75fd9f38fd859"


def call(*argv:str)->str:
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,check=True,timeout=14)
    if len(result.stdout)>4096:
        raise ValueError("unexpected command output size")
    return result.stdout.strip()


def keys(file:Path)->dict[str,str]:
    meta=file.lstat()
    if (not stat.S_ISREG(meta.st_mode) or file.is_symlink() or
        meta.st_uid!=0 or meta.st_mode&0o077 or meta.st_nlink!=1 or
        not 0<meta.st_size<100000):
        raise ValueError("untrusted config")
    rows={}
    for line in file.read_text("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name,sep,value=line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}",name) or name in rows:
            raise ValueError("unexpected env syntax")
        rows[name]=value
    return rows


def db_status()->dict[str,str]:
    # Aggregate-only, predetermined read-only SQL; never returns account ID,
    # token hash, profile, private key, billing details or an IP address.
    query="""SELECT
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
    AND o.node_receipt_sha256 ~ '^[a-f0-9]{64}$'
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
    raw=call("docker","exec","mnebyvpn-stage-postgres","psql","-X","-q",
             "-A","-t","-v","ON_ERROR_STOP=1","-U","mnebyvpn_stage",
             "-d","mnebyvpn_stage","-c",query)
    fields=raw.split("|")
    if len(fields)!=7 or any(not part.isdecimal() for part in fields[:5]):
        raise ValueError("unknown aggregate result")
    if fields[5] not in ("FRESH","STALE") or fields[6] not in ("true","false"):
        raise ValueError("missing FI state")
    labels=("ACTIVE_VPN_ENTITLEMENTS","FI_DEVICE_REQUESTS","FI_REQUESTS_PENDING",
            "FI_PEERS_APPLIED","FI_SIGNED_ACKS")
    counts={key:value for key,value in zip(labels,fields[:5])}
    counts["FI_POOL_PROOF"]=fields[5]
    counts["FI_CUSTOMER_RELEASE"]=fields[6]
    return counts


def queue_role_diagnostics()->dict[str,str]:
    sql="""SELECT
 has_table_privilege('mnebyvpn_awg_delivery','public.entitlements','SELECT')::text,
 has_table_privilege('mnebyvpn_awg_delivery','public.provisioning_state','SELECT')::text,
 has_table_privilege('mnebyvpn_awg_delivery','public.vpn_awg_device_requests','SELECT')::text,
 has_table_privilege('mnebyvpn_awg_delivery','public.vpn_awg_peer_allocations','SELECT')::text,
 has_table_privilege('mnebyvpn_awg_delivery','public.vpn_release_flags','SELECT')::text,
 has_table_privilege('mnebyvpn_awg_delivery','public.vpn_awg_node_pools','SELECT')::text,
 has_table_privilege('mnebyvpn_awg_delivery','public.vpn_node_enrollment_inventory','SELECT')::text,
 has_function_privilege('mnebyvpn_awg_delivery',
 'public.awg_controller_enqueue_fi_subscription(uuid,text,bigint)','EXECUTE')::text;
"""
    raw=call("docker","exec","mnebyvpn-stage-postgres","psql","-X","-q",
             "-A","-t","-v","ON_ERROR_STOP=1","-U","mnebyvpn_stage",
             "-d","mnebyvpn_stage","-c",sql)
    flags=raw.split("|")
    if len(flags)!=8 or any(value not in ("true","false","t","f") for value in flags):
        raise ValueError("invalid scoped worker permission probe")
    names=("ENTITLEMENTS_SELECT","PROVISIONING_SELECT","QUEUE_SELECT",
           "ALLOCATIONS_SELECT","RELEASE_SELECT","POOL_SELECT",
           "ENROLLMENT_SELECT","FI_ENQUEUE_EXECUTE")
    return {name:("true" if value in ("true","t") else "false")
            for name,value in zip(names,flags)}


def worker_journal_markers()->dict[str,str]:
    run=subprocess.run(["journalctl","-u","mnebyvpn-awg-delivery.service",
        "--since","-20 minutes","--no-pager","--output","cat"],
        stdin=subprocess.DEVNULL,capture_output=True,check=True,text=True,timeout=10)
    if len(run.stdout)>1500000:
        raise ValueError("worker journal is unbounded")
    labels=("FI_AWG_SUBSCRIPTION_ENROLLMENT_RETRY",
            "FI_AWG_SUBSCRIPTION_ENROLLMENT_QUEUED",
            "FI_AWG_DEVICE_QUEUE_RETRY",
            "AWG_DELIVERY_ACKNOWLEDGED")
    return {label:min(999,run.stdout.count(label)) for label in labels}


def main()->int:
    try:
        if (os.geteuid()!=0 or
            "188.120.254.223" not in call("ip","-o","-4","addr","show")):
            raise ValueError("wrong RU host")
        state=call("systemctl","show","-p","ActiveState","--value",
                   "mnebyvpn-awg-delivery.service")
        wd=call("systemctl","show","-p","WorkingDirectory","--value",
                "mnebyvpn-awg-delivery.service")
        release=Path(wd)
        if (state not in ("active","inactive","failed") or
            release.parent!=Path("/opt/mnebyvpn-controller/awg-worker-releases")):
            raise ValueError("worker unit changed")
        public=keys(WEB)
        worker=keys(WORKER)
        web_running=call("docker","inspect","-f","{{.State.Running}}",
                         "mnebyvpn-public-web")
        seed_public=public.get("AWG_INCY_SUBSCRIPTION_SEED","")
        seed_worker=worker.get("AWG_INCY_SUBSCRIPTION_SEED","")
        present=(bool(seed_public) and bool(seed_worker) and
                 re.fullmatch(r"[a-f0-9]{64}",seed_public) is not None)
        print("FI_AWG_SUB_WORKER_ACTIVE="+("true" if state=="active" else "false"))
        print("FI_AWG_SUB_WORKER_SOURCE="+(
            "APPROVED_20261120" if release.name==CURRENT else "OTHER_REVIEW_REQUIRED"))
        print("FI_AWG_SUB_PG_PRESENT="+(
            "yes" if (release/"node_modules/pg/package.json").is_file() else "no"))
        print("FI_AWG_SUB_WEB_RUNNING="+web_running)
        print("FI_AWG_SUB_MIXED_FEATURE="+public.get(
            "WEB_FI_AWG_IN_SUBSCRIPTION_ENABLED","missing"))
        print("FI_AWG_SUB_SEED_MATCH="+(
            "true" if present and hmac.compare_digest(seed_public,seed_worker) else "false"))
        for key,value in db_status().items():
            print("FI_AWG_SUB_"+key+"="+value)
        for key,value in queue_role_diagnostics().items():
            print("FI_AWG_SUB_ROLE_"+key+"="+value)
        for key,count in worker_journal_markers().items():
            print("FI_AWG_SUB_LOG_"+key+"="+str(count))
        print("FI_AWG_SUB_INVENTORY=READONLY_COMPLETE")
        return 0
    except (OSError,ValueError,TypeError,UnicodeError,subprocess.SubprocessError):
        print("FI_AWG_SUB_INVENTORY=BLOCKED",file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
