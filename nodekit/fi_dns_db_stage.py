#!/usr/bin/env python3
"""Apply only reviewed FI DNS migrations to the existing controller database.

No customer grant, gate enable, service restart, firewall or network change.
The runner transports encrypted backup bytes only, over independently pinned
SSH. A separate FI backup identity is never used for network authorization.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

DB = "mnebyvpn_stage"
CONTAINER = "mnebyvpn-stage-postgres"
BASE = Path("/opt/mnebyvpn/staging/backups")
OFFSITE = Path("/root/mnebyvpn-fi-dns-backups")
LOCK = Path("/run/lock/mnebyvpn-stage-deploy.lock")
MIGRATIONS = (
    "0150_fi_regional_dns_query_meter.sql",
    "0151_fi_dns_meter_verified_rpc.sql",
    "0152_fi_dns_snapshot_source.sql",
)
FUNCTIONS = (
    "public.fi_dns_meter_apply(text,uuid,text)",
    "public.fi_dns_meter_verified_apply(text,uuid,text,text,text,timestamptz)",
    "public.fi_dns_snapshot_next()",
)
MAX_DB = 128 * 1024 * 1024


def check(condition, label):
    if not condition:
        raise RuntimeError(label)


def run(args, *, data=None, stdin=None, stdout=None, timeout=30):
    result = subprocess.run(args, input=data, stdin=stdin,
                            stdout=stdout if stdout is not None else subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    check(result.returncode == 0, "command_failed_" + Path(args[0]).name)
    return result.stdout if stdout is None else b""


def private_dir(path, *, create=False):
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    check(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
          "unsafe_private_directory")


def private_file(path, limit=MAX_DB):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        check(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o077
              and 0 < s.st_size <= limit, "unsafe_private_file")
        data = f.read(limit+1)
        check(len(data) == s.st_size, "private_file_changed")
        return data


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def sha(path):
    return hashlib.sha256(private_file(path)).hexdigest()


def psql(sql, database=DB):
    return run(["docker","exec","-i",CONTAINER,"psql","-XqAt",
                "-v","ON_ERROR_STOP=1","-U",DB,"-d",database],
               data=sql.encode(), timeout=45).decode().strip()


def ledger_sql(name):
    check(name in MIGRATIONS,"unknown_migration")
    return "SELECT count(*) FROM public.deployment_schema_migrations WHERE file_name='"+name+"';"


def preflight():
    check(Path("/opt/mnebyvpn").is_dir(), "existing_controller_missing")
    check(psql("SELECT current_database();") == DB, "wrong_database")
    check(psql("SELECT EXISTS(SELECT 1 FROM public.vpn_node_enrollment_inventory WHERE node_id='fi-test-01' AND status='enrolled');") == "t", "fi_not_enrolled")
    check(psql("SELECT to_regclass('public.personal_dns_query_windows') IS NOT NULL AND to_regclass('public.personal_dns_query_reservations') IS NOT NULL AND to_regprocedure('public.finish_personal_dns_query(uuid,boolean)') IS NOT NULL;") == "t", "legacy_meter_missing")
    ledger = [psql(ledger_sql(n)) for n in MIGRATIONS]
    schema = [psql("SELECT to_regprocedure('"+n+"') IS NOT NULL;") for n in FUNCTIONS]
    if ledger == ["0"]*3 and schema == ["f"]*3:
        check(psql("SELECT to_regclass('public.fi_dns_meter_gate') IS NULL AND to_regclass('public.fi_dns_regional_credentials') IS NULL AND to_regclass('public.fi_dns_meter_requests') IS NULL AND to_regclass('public.fi_dns_meter_rpc_nonces') IS NULL AND to_regclass('public.fi_dns_snapshot_revision_seq') IS NULL;")=="t","partial_schema")
        return "pending"
    check(ledger == ["1"]*3 and schema == ["t"]*3, "partial_migration_ledger")
    verify()
    return "applied"


def verify():
    check(psql("SELECT NOT enabled FROM public.fi_dns_meter_gate WHERE singleton;")=="t","fi_gate_not_off")
    check(psql("SELECT count(*) FROM public.fi_dns_regional_credentials;")=="0","unexpected_fi_grants")
    check(psql("SELECT has_function_privilege('mnebyvpn_fi_dns_meter','public.fi_dns_meter_verified_apply(text,uuid,text,text,text,timestamptz)','EXECUTE') AND NOT has_function_privilege('mnebyvpn_fi_dns_meter','public.fi_dns_meter_apply(text,uuid,text)','EXECUTE') AND has_function_privilege('mnebyvpn_fi_dns_publisher','public.fi_dns_snapshot_next()','EXECUTE');")=="t","unexpected_fi_function_acl")


def compose(migrations):
    check(list(migrations)==list(MIGRATIONS),"migration_order_mismatch")
    chunks=["BEGIN;", "SET LOCAL lock_timeout='3s';", "SET LOCAL statement_timeout='20s';"]
    for name, data in migrations.items():
        lines=data.decode("utf8").splitlines()
        starts=[i for i,x in enumerate(lines) if x.strip()=="BEGIN;"]
        # Only strip the OUTER transaction. PL/pgSQL uses bare BEGIN.
        check(len(starts)==1 and lines[-1].strip()=="COMMIT;","unexpected_transaction_boundary")
        chunks.extend(lines[:starts[0]]+lines[starts[0]+1:-1])
        chunks.append("INSERT INTO public.deployment_schema_migrations(file_name) VALUES('"+name+"');")
    chunks.append("DO $guard$ BEGIN IF (SELECT enabled FROM public.fi_dns_meter_gate WHERE singleton) IS DISTINCT FROM false THEN RAISE EXCEPTION 'FI gate must remain off'; END IF; END $guard$;")
    chunks.append("COMMIT;")
    return "\n".join(chunks)+"\n"


def prepare(stage):
    state=preflight()
    private_dir(BASE)
    check(int(psql("SELECT pg_database_size(current_database());"))<=MAX_DB,"database_exceeds_rehearsal_budget")
    fs=os.statvfs(BASE)
    check(fs.f_bavail*fs.f_frsize>=1024**3,"insufficient_restore_disk")
    # Fresh root-only dump, outside /run. Never transfer its plaintext.
    backup=BASE/("fi-dns-pre-"+stage.name+".dump")
    fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as file:
        run(["docker","exec",CONTAINER,"pg_dump","-Fc","-U",DB,"-d",DB],
            stdout=file,timeout=90)
        file.flush()
        os.fsync(file.fileno())
    check(backup.stat().st_size<=MAX_DB and private_file(backup)[:5]==b"PGDMP","invalid_backup")
    # Real restore to a uniquely named temporary DB, never the live DB.
    temp="fi_dns_restore_"+secrets.token_hex(8)
    run(["docker","exec",CONTAINER,"createdb","-U",DB,"-T","template0",temp])
    try:
        with backup.open("rb") as f:
            run(["docker","exec","-i",CONTAINER,"pg_restore","--exit-on-error",
                 "--no-owner","--no-acl","-U",DB,"-d",temp],stdin=f,timeout=120)
        check(psql("SELECT to_regclass('public.entitlements') IS NOT NULL AND to_regclass('public.personal_dns_query_windows') IS NOT NULL;",temp)=="t","restore_verification_failed")
    finally:
        run(["docker","exec",CONTAINER,"dropdb","-U",DB,"--if-exists",temp])
    cert=stage/"backup-cert.pem"
    private_file(cert,10000)
    encrypted=stage/"backup.cms"
    # Encrypt using FI's dedicated backup public certificate. Key never leaves FI.
    run(["openssl","cms","-encrypt","-binary","-aes256","-in",str(backup),
         "-outform","DER","-out",str(encrypted),str(cert)],timeout=90)
    encrypted.chmod(0o600)
    plain_sha=sha(backup)
    cipher_sha=sha(encrypted)
    exclusive(stage/"proof",f"{int(time.time())}|{plain_sha}|{cipher_sha}|{state}\n".encode())
    print("FI_DB_BACKUP_RESTORE_VERIFIED=true")
    print("FI_DB_BACKUP_PLAIN_SHA="+plain_sha)
    print("FI_DB_BACKUP_CIPHER_SHA="+cipher_sha)


def backup_identity(stage):
    private_dir(OFFSITE,create=True)
    key=OFFSITE/"backup-key.pem"
    cert=OFFSITE/"backup-cert.pem"
    check(key.exists()==cert.exists(),"partial_offsite_backup_identity")
    if not key.exists():
        run(["openssl","req","-x509","-newkey","rsa:3072","-nodes","-days","3650",
             "-subj","/CN=MNEBYVPN FI DNS backup","-keyout",str(key),"-out",str(cert)],timeout=30)
        key.chmod(0o600)
        cert.chmod(0o600)
    private_file(key,10000)
    cert_bytes=private_file(cert,10000)
    a=run(["openssl","pkey","-in",str(key),"-pubout"])
    b=run(["openssl","x509","-in",str(cert),"-pubkey","-noout"])
    check(a==b,"offsite_backup_identity_mismatch")
    exclusive(stage/"backup-cert.pem",cert_bytes)
    print("FI_DB_BACKUP_IDENTITY_READY=true")


def store(stage, plain_sha, cipher_sha):
    private_dir(OFFSITE)
    check(re.fullmatch("[0-9a-f]{64}",plain_sha) and re.fullmatch("[0-9a-f]{64}",cipher_sha),"invalid_backup_digest")
    encrypted=stage/"backup.cms"
    check(sha(encrypted)==cipher_sha,"offsite_cipher_digest_mismatch")
    # Decrypt only into a hashing pipe, never a plaintext file or the runner.
    key=OFFSITE/"backup-key.pem";cert=OFFSITE/"backup-cert.pem"
    private_file(key,10000);private_file(cert,10000)
    proc=subprocess.Popen(["openssl","cms","-decrypt","-binary","-inform","DER",
                           "-in",str(encrypted),"-recip",str(cert),"-inkey",str(key)],
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    digest=hashlib.sha256()
    total=0
    try:
        while True:
            block=proc.stdout.read(65536)
            if not block: break
            total+=len(block)
            check(total<=MAX_DB,"offsite_backup_too_large")
            digest.update(block)
        check(proc.wait(timeout=15)==0 and digest.hexdigest()==plain_sha,"offsite_decryption_mismatch")
    finally:
        if proc.poll() is None:
            proc.kill();proc.wait()
    target=OFFSITE/(stage.name+".cms")
    exclusive(target,private_file(encrypted))
    check(sha(target)==cipher_sha,"offsite_readback_failed")
    exclusive(OFFSITE/(stage.name+".sha256"),(plain_sha+"|"+cipher_sha+"\n").encode())
    print("FI_DB_OFFSITE_BACKUP_VERIFIED="+cipher_sha)


def apply(stage, receipt):
    proof=private_file(stage/"proof",512).decode().strip().split("|")
    check(len(proof)==4 and receipt==proof[2] and 0<=time.time()-int(proof[0])<=900,"missing_fresh_backup_receipt")
    check(sha(stage/"backup.cms")==receipt,"controller_backup_digest_mismatch")
    state=preflight()
    check(state==proof[3],"schema_changed_since_backup")
    if state=="pending":
        sql=compose({name:private_file(stage/name,100000) for name in MIGRATIONS})
        psql(sql)
    verify()
    check(all(psql(ledger_sql(n))=="1" for n in MIGRATIONS),"migration_ledger_missing")
    print("FI_DB_SCHEMA_APPLIED=true;FI_GATE_OFF=true;FI_GRANTS=0;SERVICES_UNCHANGED=true")


def main():
    os.umask(0o077)
    check(os.geteuid()==0,"root_required")
    ap=argparse.ArgumentParser()
    ap.add_argument("action",choices=("identity","prepare","store","apply"))
    ap.add_argument("stage",type=Path)
    ap.add_argument("digests",nargs="*")
    args=ap.parse_args()
    stage=args.stage
    check(stage.parent==Path("/run") and re.fullmatch(r"fi-dns-db-[0-9]+-[0-9]+",stage.name),"invalid_stage_path")
    private_dir(stage)
    if args.action=="identity":
        backup_identity(stage)
    elif args.action=="store":
        check(len(args.digests)==2,"missing_backup_digests")
        store(stage,*args.digests)
    else:
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.action=="prepare":
                prepare(stage)
            else:
                check(len(args.digests)==1,"missing_offsite_receipt")
                apply(stage,args.digests[0])
        finally:
            os.close(fd)


if __name__=="__main__":
    try:
        main()
    except (RuntimeError,OSError,ValueError,subprocess.SubprocessError) as exc:
        # No SQL, password, backup bytes or customer data in Actions output.
        label=str(exc) if isinstance(exc,RuntimeError) and re.fullmatch("[a-z0-9_]+",str(exc)) else "stage_failed"
        print("FI_DB_STAGE_BLOCKED="+label,file=sys.stderr)
        raise SystemExit(2)
