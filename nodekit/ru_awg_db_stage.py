#!/usr/bin/env python3
"""RU188 idempotent, least-privileged AWG DB credential stage.

Read-only schema preflight first. Stage dedicated DB role, 0600 worker env and
the already pinned separate SSH identity. NEVER start worker, install peers,
release VPN, change entitlements or publish subscriptions.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
from urllib.parse import urlsplit

RU="188.120.254.223"
ROOT=Path("/root/mnebyvpn-controller")
ENV=ROOT/"config/awg-delivery.env"
FI_ENV=ROOT/"config/fi-enrollment.env"
ROLE="mnebyvpn_awg_delivery"
DB="mnebyvpn_stage"
CONTAINER="mnebyvpn-stage-postgres"
PORT="55433"
SHA="e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
SIGNER=ROOT/"controller-signing-key.pem"
KEY=ROOT/"awg-delivery-ssh"
PIN=ROOT/"awg-delivery-known_hosts"
TABLES=("vpn_awg_command_outbox","vpn_awg_peer_allocations","vpn_awg_node_pools",
        "vpn_node_enrollment_inventory","entitlements","vpn_release_flags")
class Halt(ValueError):pass
def fail(code):
    print("AWG_DB_STAGE_BLOCKED="+code,file=sys.stderr)
    raise Halt(code)
def on_ru():
    if os.geteuid():return False
    for _,name in socket.if_nameindex():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            try:
                raw=fcntl.ioctl(sock.fileno(),0x8915,struct.pack("256s",name.encode()))
                if socket.inet_ntoa(raw[20:24])==RU:return True
            except OSError:pass
    return False
def owned_dir(path):
    for d in (path,*path.parents):
        try:s=d.lstat()
        except OSError:fail("missing_directory")
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
            fail("untrusted_directory")
    if path in (ROOT,ROOT/"config") and path.stat().st_mode&0o077:
        fail("controller_secrets_directory_not_private")
def read(path,limit=8192):
    owned_dir(path.parent)
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except OSError:fail("protected_file_unavailable")
    try:
        s=os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or
            s.st_mode&0o077 or s.st_nlink!=1 or not 1<=s.st_size<=limit):
            fail("untrusted_protected_file")
        data=os.read(fd,limit+1)
        if len(data)!=s.st_size:fail("protected_file_changed")
        return data
    finally:os.close(fd)
def run(args,stdin=None):
    try:p=subprocess.run(args,input=stdin,text=True,capture_output=True,timeout=25)
    except (OSError,subprocess.TimeoutExpired):fail("canonical_command_unavailable")
    if p.returncode:fail("canonical_command_failed")
    return p.stdout.strip()
def sql(query):
    return run(["docker","exec","-i",CONTAINER,"psql","-X","-q","-At",
                "-v","ON_ERROR_STOP=1","-U",DB,"-d",DB],stdin=query)
def preflight():
    if not on_ru():fail("not_existing_ru188")
    owned_dir(ROOT)
    read(SIGNER)
    spki=read(ROOT/"controller-public.spki",100)
    if len(spki)!=44 or hashlib.sha256(spki).hexdigest()!=SHA:
        fail("controller_signature_pin_invalid")
    read(KEY)
    key=read(PIN,512)
    if key!=read(ROOT/"fi-known_hosts",512):
        fail("distinct_awg_ssh_host_pin_mismatch")
    existing=read(FI_ENV).decode("ascii")
    values={}
    for line in existing.splitlines():
        if "=" not in line:fail("registrar_env_malformed")
        k,v=line.split("=",1)
        if k in values:fail("duplicate_registrar_env")
        values[k]=v
    url=values.get("DATABASE_URL","")
    try:address=urlsplit(url)
    except ValueError:fail("registrar_db_uri_invalid")
    if (address.scheme!="postgresql" or address.hostname!="127.0.0.1" or
        address.port!=int(PORT) or address.path!="/"+DB or address.query):
        fail("not_enrolled_canonical_db")
    info=json.loads(run(["docker","inspect",CONTAINER]))
    if (len(info)!=1 or not info[0].get("State",{}).get("Running") or
        info[0].get("HostConfig",{}).get("PortBindings",{}).get("5432/tcp")!=
        [{"HostIp":"127.0.0.1","HostPort":PORT}]):
        fail("canonical_postgres_not_loopback")
    tables=sql("SELECT "+",".join(
        "to_regclass('public."+n+"')::text" for n in TABLES)+";").split("|")
    if len(tables)!=len(TABLES) or any(x!=name for x,name in zip(tables,TABLES)):
        fail("awg_schema_not_migrated")
    flag=sql("SELECT enabled::text FROM public.vpn_release_flags "
             "WHERE feature='vpn_awg_clients';")
    if flag!="false":fail("customer_awg_release_not_disabled")
    active=run(["systemctl","is-active","mnebyvpn-awg-delivery.service"])
    # Nonzero inactive is normal; use separate check below if needed.
    if active=="active":fail("refuse_active_delivery_worker")
def fields(password):
    return {
        "MNEBYVPN_ENV":"production",
        "MNEBYVPN_AWG_DELIVERY_WORKER":"disabled",
        "DATABASE_URL":f"postgresql://{ROLE}:{password}@127.0.0.1:{PORT}/{DB}",
        "AWG_CONTROLLER_SIGNING_KEY_FILE":str(SIGNER),
        "AWG_CONTROLLER_PUBLIC_SHA256":SHA,
        "AWG_CONTROLLER_SSH_IDENTITY_FILE":str(KEY),
        "AWG_CONTROLLER_SSH_KNOWN_HOSTS_FILE":str(PIN),
    }
def existing_env():
    if not ENV.exists() and not ENV.is_symlink():
        return None
    values={}
    for line in read(ENV).decode("ascii").splitlines():
        if line.count("=")!=1:fail("awg_env_malformed")
        k,v=line.split("=",1)
        if not re.fullmatch("[A-Z0-9_]+",k) or k in values:fail("awg_env_unknown_or_duplicate_field")
        values[k]=v
    match=re.fullmatch(
        r"postgresql://mnebyvpn_awg_delivery:([a-f0-9]{64})@127\.0\.0\.1:55433/mnebyvpn_stage",
        values.get("DATABASE_URL",""))
    if not match or values!=fields(match.group(1)):
        fail("awg_env_is_not_reviewed_staging_config")
    return match.group(1)
def main():
    if sys.argv[1:]:fail("unexpected_arguments")
    os.umask(0o077)
    preflight()
    lock=ROOT/"awg-db-stage.lock"
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:
            fail("unsafe_bootstrap_lock")
        fcntl.flock(fd,fcntl.LOCK_EX)
        old=existing_env()
        password=old or secrets.token_hex(32)
        found=sql("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='"+ROLE+"')::text;")
        if found not in ("true","false"):fail("unknown_postgres_role")
        if (old is None) != (found=="false"):
            fail("staged_role_environment_disagree")
        create=(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{password}' "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;") if found=="false" else ""
        # Deliberately NO UPDATE on entitlements or release flags: the existing
        # worker uses FOR SHARE which must be refactored behind a safe DB API
        # before permission/activation can be granted.
        grants=f"""
BEGIN;
{create}
GRANT CONNECT ON DATABASE {DB} TO {ROLE};
GRANT USAGE ON SCHEMA public TO {ROLE};
GRANT SELECT ON public.entitlements,public.vpn_release_flags,
  public.vpn_node_enrollment_inventory,public.vpn_awg_node_pools,
  public.vpn_awg_peer_allocations,public.vpn_awg_command_outbox TO {ROLE};
GRANT UPDATE(state,claimed_at,attempts,applied_at,node_receipt_sha256)
  ON public.vpn_awg_command_outbox TO {ROLE};
GRANT UPDATE(revision,expires_at,state,last_signed_at,last_command_sha256,applied_at)
  ON public.vpn_awg_peer_allocations TO {ROLE};
GRANT INSERT ON public.vpn_awg_command_outbox,public.vpn_awg_peer_allocations TO {ROLE};
COMMIT;"""
        sql(grants)
        audit=sql(
          "SELECT has_table_privilege('"+ROLE+"','public.entitlements','UPDATE')::text,"
          "has_table_privilege('"+ROLE+"','public.vpn_release_flags','UPDATE')::text,"
          "has_table_privilege('"+ROLE+"','public.vpn_awg_command_outbox','SELECT')::text,"
          "has_table_privilege('"+ROLE+"','public.vpn_awg_peer_allocations','SELECT')::text,"
          "has_table_privilege('"+ROLE+"','public.entitlements','SELECT')::text;"
        )
        if audit!="false|false|true|true|true":
            fail("unexpected_billing_write_privileges")
        if old is None:
            content="".join(k+"="+v+"\n" for k,v in fields(password).items()).encode()
            out=os.open(ENV,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(out,"wb") as dst:
                    dst.write(content);dst.flush();os.fsync(dst.fileno())
            except BaseException:
                ENV.unlink(missing_ok=True)
                raise
        # Deliberately no approval marker or systemctl start.
        if (ROOT/"approvals/awg-delivery.enable").exists():
            fail("unexpected_live_delivery_approval")
        print("AWG_DB_ROLE=scoped;AWG_DB_ENV=protected;BILLING_WRITES=false;"
              "WORKER_ENABLED=false;AWG_RELEASE=false;IDEMPOTENT="+
              str(old is not None).lower())
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)
if __name__=="__main__":
    try:main()
    except (Halt,OSError,ValueError,TypeError,UnicodeError,subprocess.SubprocessError):
        raise SystemExit(2)
