#!/usr/bin/env python3
"""One-time FI217 controller DB bootstrap, existing RU188 ONLY.

Requires previously pinned controller and FI public Ed25519 identities, running
canonical existing MNEBYVPN PostgreSQL with loopback-only host port, and exact
enrollment schema. Provisions a dedicated limited DB role, approved FI inventory
row and private EnvironmentFile; never publishes subscribers or starts services.
All credentials are generated and stay on RU188. Repeat runs are idempotent.
"""
from __future__ import annotations
import base64
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

RU="188.120.254.223"
ROOT=Path("/root/mnebyvpn-controller")
NODE="fi-test-01"
HOST="fi.mnebyvpn.site"
DB="mnebyvpn_stage"
DB_CONTAINER="mnebyvpn-stage-postgres"
DB_ROLE="mnebyvpn_fi_enroll"
PORT="55433"
CONTROLLER_SHA="e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA="c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
SPKI_HEADER=bytes.fromhex("302a300506032b6570032100")
ENV=ROOT/"config/fi-enrollment.env"
APPROVAL=ROOT/"approvals/fi-enrollment.enable"


class Stop(Exception):
    pass


def halt(label):
    print("FI_DB_BOOTSTRAP_BLOCKED="+label,file=sys.stderr)
    raise Stop(label)


def is_host(ip):
    for _,name in socket.if_nameindex():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            try:
                b=fcntl.ioctl(sock.fileno(),0x8915,struct.pack("256s",name.encode()))
                if socket.inet_ntoa(b[20:24])==ip:return True
            except OSError:pass
    return False


def root_directory(path,create=False):
    if create and not path.exists() and not path.is_symlink():
        try: path.mkdir(mode=0o700)
        except OSError:halt("protected_directory_creation_failed")
    for d in (path,*path.parents):
        try:s=d.lstat()
        except OSError:halt("protected_root_directory_missing")
        if (not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022 or
                (d in (path,ROOT) and s.st_mode & 0o077)):
            halt("unsafe_protected_directory")


def protected(path,max_size=8192):
    root_directory(path.parent)
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except OSError:halt("protected_file_missing:"+path.name)
    try:
        s=os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or
                s.st_mode & 0o077 or s.st_nlink!=1 or
                not 1<=s.st_size<=max_size):
            halt("unsafe_protected_file:"+path.name)
        data=os.read(fd,max_size+1)
        if len(data)!=s.st_size:halt("unstable_protected_file")
        return data
    finally:os.close(fd)


def public_spki(path,digest):
    data=protected(path,100)
    if (len(data)!=44 or not data.startswith(SPKI_HEADER) or
            hashlib.sha256(data).hexdigest()!=digest):
        halt("untrusted_public_identity")
    return data


def exec_public(argv,*,input_text=None,timeout=20):
    try:
        p=subprocess.run(argv,input=input_text,text=True,capture_output=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        halt("local_canonical_db_command_unavailable")
    if p.returncode!=0:
        # SQL stderr can contain secrets. Never echo it to CI.
        halt("local_canonical_db_command_failed")
    return p.stdout.strip()


def sql(statement):
    return exec_public(["docker","exec","-i",DB_CONTAINER,"psql","-X","-q","-At",
                        "-v","ON_ERROR_STOP=1","-U",DB,"-d",DB],
                       input_text=statement,timeout=30)


def canonical_database():
    raw=exec_public(["docker","inspect",DB_CONTAINER])
    data=json.loads(raw)
    if len(data)!=1 or not data[0].get("State",{}).get("Running"):
        halt("canonical_db_container_not_running")
    ports=data[0].get("HostConfig",{}).get("PortBindings",{}).get("5432/tcp",[])
    if (not isinstance(ports,list) or len(ports)!=1 or
            ports[0].get("HostIp")!="127.0.0.1" or
            ports[0].get("HostPort")!=PORT):
        halt("canonical_db_host_port_not_pinned_to_loopback")
    check=sql("SELECT current_database(), "
              "to_regclass('public.vpn_node_enrollment_inventory')::text, "
              "to_regclass('public.vpn_node_enrollment_challenges')::text, "
              "to_regclass('public.entitlements')::text;")
    fields=check.split("|")
    if len(fields)!=4 or fields[0]!=DB or any(not v for v in fields[1:]):
        halt("wrong_canonical_database_or_missing_migrations")
    return True


def env_fields(password):
    return {
        "MNEBYVPN_ENV":"production",
        "MNEBYVPN_FI_ENROLLMENT":"enabled",
        "DATABASE_URL":f"postgresql://{DB_ROLE}:{password}@127.0.0.1:{PORT}/{DB}",
        "AWG_CONTROLLER_SIGNING_KEY_FILE":str(ROOT/"controller-signing-key.pem"),
        "AWG_CONTROLLER_PUBLIC_SHA256":CONTROLLER_SHA,
        "FI_ENROLL_SSH_KEY_FILE":str(ROOT/"fi-enrollment-ssh"),
        "FI_ENROLL_KNOWN_HOSTS_FILE":str(ROOT/"fi-known_hosts"),
        "FI_ENROLL_NODE_PUBLIC_SPKI_FILE":str(ROOT/"fi-node-public.spki"),
    }


def environment():
    root_directory(ENV.parent,create=True)
    if ENV.exists() or ENV.is_symlink():
        content=protected(ENV)
        values={}
        for line in content.decode("ascii").splitlines():
            if line.count("=")<1:halt("unexpected_registrar_environment")
            key,val=line.split("=",1)
            if not re.fullmatch(r"[A-Z0-9_]+",key) or key in values:
                halt("unexpected_registrar_environment")
            values[key]=val
        url=values.get("DATABASE_URL","")
        match=re.fullmatch(
            r"postgresql://mnebyvpn_fi_enroll:([a-f0-9]{64})@127\.0\.0\.1:55433/mnebyvpn_stage",
            url,
        )
        if not match or values!=env_fields(match.group(1)):
            halt("registrar_environment_does_not_match_canonical_database")
        return match.group(1),False
    password=secrets.token_hex(32)
    content="".join(k+"="+v+"\n" for k,v in env_fields(password).items()).encode()
    fd=os.open(ENV,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(content);out.flush();os.fsync(out.fileno())
        parent=os.open(ENV.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    except Exception:
        ENV.unlink(missing_ok=True)
        raise
    return password,True


def approved_ssh_host():
    pin=protected(ROOT/"fi-known_hosts",512).decode("ascii").strip().split()
    if len(pin)!=3 or pin[0]!=HOST or pin[1]!="ssh-ed25519":
        halt("fi_known_hosts_not_pinned")
    try:
        raw=base64.b64decode(pin[2],validate=True)
    except ValueError:halt("invalid_fi_known_hosts_key")
    if len(raw)!=51 or raw[:15]!=b"\x00\x00\x00\x0bssh-ed25519":
        halt("invalid_fi_known_hosts_key")


def verify_role_and_approve(spki,password,new_environment):
    # All material above is pinned and reviewed; no arbitrary SQL user input.
    existing=sql(f"SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{DB_ROLE}')::text;")
    if existing not in ("true","false"):halt("unknown_fi_db_role_state")
    if new_environment and existing=="true":
        halt("existing_fi_db_role_without_previous_protected_config")
    create=""
    if existing=="false":
        if not re.fullmatch(r"[a-f0-9]{64}",password):halt("unsafe_generated_password")
        create=(f"CREATE ROLE {DB_ROLE} LOGIN PASSWORD '{password}' "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;")
    # The identity enters planned first. Operator authorization for the exact
    # reviewed FI key is this immutable approved deployment source and request.
    statements=f"""
BEGIN;
{create}
GRANT CONNECT ON DATABASE {DB} TO {DB_ROLE};
GRANT USAGE ON SCHEMA public TO {DB_ROLE};
GRANT SELECT,UPDATE(status,enrolled_at) ON public.vpn_node_enrollment_inventory TO {DB_ROLE};
GRANT SELECT,INSERT,UPDATE(consumed_at) ON public.vpn_node_enrollment_challenges TO {DB_ROLE};
DO $approved$
DECLARE old_record RECORD;
BEGIN
  SELECT node_id,endpoint_host,identity_public_spki,status
    INTO old_record FROM public.vpn_node_enrollment_inventory
    WHERE node_id='{NODE}' FOR UPDATE;
  IF FOUND THEN
    IF old_record.endpoint_host<>'{HOST}'
      OR old_record.identity_public_spki<>'{spki}'
      OR old_record.status NOT IN ('planned','approved','enrolled') THEN
      RAISE EXCEPTION 'FI identity or existing approval conflict';
    END IF;
  ELSE
    INSERT INTO public.vpn_node_enrollment_inventory
      (node_id,endpoint_host,identity_public_spki,status)
      VALUES ('{NODE}','{HOST}','{spki}','planned');
  END IF;
  UPDATE public.vpn_node_enrollment_inventory
    SET status='approved',approved_at=clock_timestamp()
    WHERE node_id='{NODE}' AND status='planned'
      AND endpoint_host='{HOST}' AND identity_public_spki='{spki}';
END;
$approved$;
COMMIT;
"""
    if not re.fullmatch(r"[A-Za-z0-9_-]{59}",spki):
        halt("untrusted_fi_inventory_encoding")
    sql(statements)
    verify=sql(f"SELECT status,endpoint_host,identity_public_spki,"
               f"(approved_at IS NOT NULL)::text FROM public.vpn_node_enrollment_inventory "
               f"WHERE node_id='{NODE}';")
    if verify not in (f"approved|{HOST}|{spki}|true",
                      f"enrolled|{HOST}|{spki}|true"):
        halt("canonical_inventory_approval_not_verified")


def approval_marker():
    root_directory(APPROVAL.parent,create=True)
    material=b"FI217_CONTROLLER_REGISTRATION_ONLY\n"
    if APPROVAL.exists() or APPROVAL.is_symlink():
        if protected(APPROVAL,512)!=material:
            halt("unexpected_fi_approval_marker")
        return
    fd=os.open(APPROVAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as out:
        out.write(material);out.flush();os.fsync(out.fileno())
    parent=os.open(APPROVAL.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent)
    finally:os.close(parent)


def main():
    if os.geteuid()!=0 or not is_host(RU):
        halt("not_existing_controller188")
    root_directory(ROOT)
    public_spki(ROOT/"controller-public.spki",CONTROLLER_SHA)
    node=public_spki(ROOT/"fi-node-public.spki",NODE_SHA)
    approved_ssh_host()
    protected(ROOT/"controller-signing-key.pem",8192)
    protected(ROOT/"fi-enrollment-ssh",8192)
    canonical_database()
    pw,new=environment()
    approved=base64.urlsafe_b64encode(node).decode("ascii").rstrip("=")
    verify_role_and_approve(approved,pw,new)
    approval_marker()
    print("FI_DB_ROLE=scoped;FI_DB_INVENTORY=approved_or_enrolled;"
          "FI_CONTROLLER_CONFIG=protected;SUBSCRIBERS_PUBLISHED=false")


if __name__=="__main__":
    try:main()
    except (Stop,OSError,ValueError,TypeError,UnicodeError,KeyError):
        raise SystemExit(2)
