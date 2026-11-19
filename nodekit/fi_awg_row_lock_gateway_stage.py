#!/usr/bin/env python3
"""RU188-only, unattended, additive AWG row-lock SQL gateway stage.

Install the EXACT source-pinned Mnebyvpn 0135 migration once; safely verify
an existing installation on reruns. Never create or modify subscriptions,
peer routes, billing entries, SSH secrets, VPN services or worker activation.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys

RU="188.120.254.223"
ROOT=Path("/root/mnebyvpn-controller")
CONTAINER="mnebyvpn-stage-postgres"
DB="mnebyvpn_stage"
PORT="55433"
ROLE="mnebyvpn_awg_delivery"
CONTROLLER_SHA="e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
FUNCS=(
    "awg_worker_lock_entitlement(uuid)",
    "awg_worker_lock_node(text)",
    "awg_worker_lock_pool(text)",
    "awg_worker_lock_pool_node(text)",
)


class Blocked(ValueError):
    pass


def stop(message: str) -> None:
    print("FI_AWG_ROW_LOCK_STAGE_BLOCKED="+message,file=sys.stderr)
    raise Blocked(message)


def is_ru188() -> bool:
    if os.geteuid()!=0:return False
    for _,name in socket.if_nameindex():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            try:
                data=fcntl.ioctl(sock.fileno(),0x8915,struct.pack("256s",name.encode()))
                if socket.inet_ntoa(data[20:24])==RU:return True
            except OSError:pass
    return False


def read_protected(path:Path, limit:int=8192) -> bytes:
    for directory in path.parents:
        try:st=directory.lstat()
        except OSError:stop("missing_root_ancestry")
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022):
            stop("unsafe_root_ancestry")
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except OSError:stop("missing_verified_asset")
    try:
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or
            st.st_mode&0o077 or st.st_nlink!=1 or
            not 1<=st.st_size<=limit):
            stop("unsafe_verified_asset")
        raw=os.read(fd,limit+1)
        if len(raw)!=st.st_size:stop("asset_changed_during_read")
        return raw
    finally:os.close(fd)


def run(args:list[str],input_text:str|None=None,timeout:int=30) -> str:
    try:
        process=subprocess.run(args,input=input_text,text=True,
                               capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        stop("canonical_command_unavailable")
    if process.returncode:
        # Never expose credentials, server SQL payload, user billing rows or
        # postgres error text to runner logs.
        stop("canonical_command_failed")
    return process.stdout.strip()


def sql(query:str)->str:
    return run(["/usr/bin/docker","exec","-i",CONTAINER,
                "psql","-X","-q","-At","-v","ON_ERROR_STOP=1",
                "-U",DB,"-d",DB],query)


def preflight() -> None:
    if not is_ru188():stop("not_existing_ru188_root")
    identity=read_protected(ROOT/"controller-public.spki",100)
    if (len(identity)!=44 or
        hashlib.sha256(identity).hexdigest()!=CONTROLLER_SHA):
        stop("controller_identity_untrusted")
    env=read_protected(ROOT/"config/awg-delivery.env").decode("ascii")
    if not re.search(r"^MNEBYVPN_AWG_DELIVERY_WORKER=disabled$",env,re.M):
        stop("awg_worker_environment_not_disabled")
    if not re.search(r"^DATABASE_URL=postgresql://mnebyvpn_awg_delivery:[a-f0-9]{64}@127\.0\.0\.1:55433/mnebyvpn_stage$",env,re.M):
        stop("unknown_canonical_worker_database")
    if (ROOT/"approvals/awg-delivery.enable").exists():
        stop("awg_worker_approval_already_enabled")
    try:
        p=subprocess.run(["/usr/bin/systemctl","is-active","--quiet",
                          "mnebyvpn-awg-delivery.service"],timeout=8)
    except (OSError,subprocess.TimeoutExpired):
        stop("worker_service_probe_unavailable")
    if p.returncode==0:stop("refuse_gateway_stage_on_active_worker")
    import json
    container=json.loads(run(["/usr/bin/docker","inspect",CONTAINER]))
    if len(container)!=1 or not container[0].get("State",{}).get("Running"):
        stop("canonical_postgres_not_running")
    binding=container[0].get("HostConfig",{}).get("PortBindings",{}).get("5432/tcp")
    if (not isinstance(binding,list) or len(binding)!=1 or
        binding[0].get("HostIp")!="127.0.0.1" or
        binding[0].get("HostPort")!=PORT):
        stop("canonical_postgres_not_loopback_pinned")
    rows=sql(
      "SELECT current_database(),(SELECT status FROM public.vpn_node_enrollment_inventory "
      "WHERE node_id='fi-test-01'),(SELECT enabled::text FROM public.vpn_release_flags "
      "WHERE feature='vpn_awg_clients');")
    if rows!="mnebyvpn_stage|enrolled|false":
        stop("fi_enrollment_or_customer_release_not_safe")
    role=sql("SELECT rolcanlogin::text,rolsuper::text,rolinherit::text "
             "FROM pg_catalog.pg_roles WHERE rolname='mnebyvpn_awg_delivery';")
    if role!="true|false|false":
        stop("worker_role_not_scoped_or_missing")
    for table in ("entitlements","vpn_release_flags",
                  "vpn_node_enrollment_inventory","vpn_awg_node_pools"):
        actual=sql(
          "SELECT has_table_privilege('mnebyvpn_awg_delivery',"
          f"'public.{table}','SELECT')::text,"
          "has_any_column_privilege('mnebyvpn_awg_delivery',"
          f"'public.{table}','UPDATE')::text;")
        if actual!="true|false":
            stop("worker_billing_or_node_write_privilege_detected")


def installed_metadata() -> str:
    signatures=",".join(f"'{name}'" for name in FUNCS)
    query=f"""
SELECT p.proname,p.prosecdef::text,
       (p.proowner=(SELECT oid FROM pg_roles WHERE rolname='mnebyvpn_stage'))::text,
       (array_to_string(p.proconfig,';') LIKE '%search_path=pg_catalog, public%')::text,
       has_function_privilege('{ROLE}',p.oid,'EXECUTE')::text,
       COALESCE((SELECT bool_or(a.grantee=0 AND a.privilege_type='EXECUTE')
                  FROM aclexplode(p.proacl) a),false)::text
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND (p.oid::regprocedure::text = ANY(ARRAY[{signatures}])
  OR ('public.'||p.oid::regprocedure::text) = ANY(ARRAY[{signatures}]))
ORDER BY p.proname;"""
    return sql(query)


def check_installed() -> bool:
    # Return only bounded schema metadata; no user records or credentials.
    data=installed_metadata().splitlines()
    if not data:return False
    wanted={f.split("(")[0] for f in FUNCS}
    if len(data)!=4:return False
    for line in data:
        fields=line.split("|")
        if len(fields)!=6 or fields[0] not in wanted or fields[1:]!=[
                "true","true","true","true","false"]:
            return False
        wanted.remove(fields[0])
    return not wanted


def grant_gateway() -> None:
    # The migration explicitly grants EXECUTE to the EXISTING dedicated role
    # and none to PUBLIC. Never grant billing UPDATE to satisfy row locks.
    if not check_installed():stop("gateway_owner_acl_or_signature_mismatch")
    # Test actual restricted role execution in a rolled-back transaction.
    output=sql("""
BEGIN;
SET LOCAL ROLE mnebyvpn_awg_delivery;
SELECT count(*) FROM public.awg_worker_lock_entitlement(
 '00000000-0000-4000-8000-000000000000'::uuid);
SELECT count(*) FROM public.awg_worker_lock_node('fi-test-01');
SELECT count(*) FROM public.awg_worker_lock_pool('fi-test-01');
SELECT count(*) FROM public.awg_worker_lock_pool_node('fi-test-01');
ROLLBACK;
""")
    values=output.splitlines()
    if len(values)!=4 or values[0]!="0" or values[1]!="1" or any(
            not re.fullmatch(r"\d+",item) for item in values[2:]):
        stop("scoped_worker_gateway_role_probe_failed")


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sql-file",type=Path,required=True)
    p.add_argument("--sha256",required=True)
    args=p.parse_args()
    if not re.fullmatch(r"[a-f0-9]{64}",args.sha256):
        stop("invalid_approved_sql_digest")
    preflight()
    # A disposable, root-only SQL file is shipped from an immutable GitHub
    # commit by the Action. No SQL is acquired from external user input.
    blob=read_protected(args.sql_file,14000)
    if hashlib.sha256(blob).hexdigest()!=args.sha256:
        stop("reviewed_sql_digest_mismatch")
    decoded=blob.decode("utf-8")
    if (not decoded.startswith("-- Dedicated AWG worker safe row-lock gateway.") or
        decoded.count("LANGUAGE sql SECURITY DEFINER")!=4 or
        decoded.count("REVOKE ALL ON FUNCTION public.")!=4 or
        "TO mnebyvpn_awg_delivery;" not in decoded):
        stop("unreviewed_awg_sql_migration")
    lock=ROOT/"awg-row-lock-stage.lock"
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:
            stop("unsafe_row_lock_stage_lock")
        fcntl.flock(fd,fcntl.LOCK_EX)
        existing=installed_metadata()
        if not existing:
            sql(decoded)
            print("FI_AWG_ROW_LOCK_MIGRATION=installed")
        elif not check_installed():
            stop("unreviewed_preexisting_row_lock_gateway")
        else:
            print("FI_AWG_ROW_LOCK_MIGRATION=idempotent")
        grant_gateway()
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)
    print("FI_AWG_ROW_LOCK_GATEWAY_READY=true;WORKER_STARTED=false;"
          "BILLING_WRITE_PRIVILEGES=false;CUSTOMER_RELEASE=false")


if __name__=="__main__":
    try:
        main()
    except (Blocked,OSError,ValueError,TypeError,KeyError,UnicodeError,
            subprocess.SubprocessError):
        raise SystemExit(2)
