#!/usr/bin/env python3
"""Stage and start only isolated loopback FI controller services.

No change to existing controller runtime, SSH daemon, VPN, DNS ingress,
website, bot, or FI release flag. Stop on existing unexpected assets.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import fcntl

from fi_dns_db_stage import psql, preflight, private_dir, private_file, exclusive

ROOT=Path("/root/mnebyvpn-controller")
RUNTIME=Path("/opt/mnebyvpn-controller/current")
DEST=Path("/opt/mnebyvpn-fi-dns-controller")
STATE=Path("/var/lib/mnebyvpn-fi-dns-controller")
UNITDIR=Path("/etc/systemd/system")
MODES=("meter","publisher")
MODULES=("fi_dns_controller_worker.mjs","fi-dns-meter-loopback.ts",
         "fi-dns-meter-rpc.ts","fi-dns-snapshot-publisher.ts",
         "fi-personal-dns-signed-snapshot.ts")
CONTROLLER_PIN="e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_PIN="c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"


def check(ok,label):
    if not ok:
        raise RuntimeError(label)


def call(*args,timeout=20,env=None):
    result=subprocess.run(args,capture_output=True,timeout=timeout,env=env)
    check(result.returncode==0,"runtime_command_failed")
    return result.stdout


def unit(mode):
    return "mnebyvpn-fi-dns-"+mode+".service"


def exact_file(path,data):
    if path.exists() or path.is_symlink():
        check(private_file(path,max(len(data),1))==data,"existing_asset_drift")
    else:
        exclusive(path,data)


def create_role(mode):
    group="mnebyvpn_fi_dns_"+mode
    role=group+"_runtime"
    path=ROOT/"config"/("fi-dns-"+mode+".env")
    prefix="DATABASE_URL=postgresql://"+role+":"
    suffix="@127.0.0.1:55433/mnebyvpn_stage\n"
    exists=psql("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='"+role+"');")
    check(exists in ("t","f"),"unknown_login_role")
    if path.exists() or path.is_symlink():
        text=private_file(path,512).decode("ascii")
        match=re.fullmatch(re.escape(prefix)+"([a-f0-9]{64})"+re.escape(suffix),text)
        check(match is not None,"invalid_scoped_env")
        password=match.group(1)
    else:
        check(exists=="f","existing_login_without_config")
        password=secrets.token_hex(32)
        exclusive(path,(prefix+password+suffix).encode())
    if exists=="f":
        psql("BEGIN; CREATE ROLE "+role+" LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT "+("8" if mode=="meter" else "1")+" PASSWORD '"+password+"'; GRANT "+group+" TO "+role+"; GRANT CONNECT ON DATABASE mnebyvpn_stage TO "+role+"; COMMIT;")
    check(psql("SELECT rolcanlogin AND rolinherit AND NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND (SELECT count(*) FROM pg_auth_members WHERE member=r.oid)=1 AND pg_has_role(rolname,'"+group+"','USAGE') FROM pg_roles r WHERE rolname='"+role+"';")=="t","unexpected_runtime_role")
    function=("public.fi_dns_meter_verified_apply(text,uuid,text,text,text,timestamptz)" if mode=="meter" else "public.fi_dns_snapshot_next()")
    other=("public.fi_dns_snapshot_next()" if mode=="meter" else "public.fi_dns_meter_verified_apply(text,uuid,text,text,text,timestamptz)")
    check(psql("SELECT has_function_privilege('"+role+"','"+function+"','EXECUTE') AND NOT has_function_privilege('"+role+"','"+other+"','EXECUTE') AND NOT has_function_privilege('"+role+"','public.fi_dns_meter_apply(text,uuid,text)','EXECUTE') AND NOT has_table_privilege('"+role+"','public.entitlements','SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('"+role+"','public.fi_dns_regional_credentials','SELECT,INSERT,UPDATE,DELETE');")=="t","runtime_privileges_too_broad")
    # Check ALL SECURITY DEFINER functions in the application schema, not
    # only the FI RPCs. Public grants in older migrations must not silently
    # turn a new network-facing login into a general billing operator.
    check(psql("SELECT NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef AND p.oid<>'"+function+"'::regprocedure AND has_function_privilege('"+role+"',p.oid,'EXECUTE'));")=="t","unexpected_security_definer_privilege")
    env=dict(os.environ,DATABASE_URL=prefix.removeprefix("DATABASE_URL=")+password+suffix.strip())
    call(str(RUNTIME/"bin/node"),"--input-type=module","-e",
         "import pg from '/opt/mnebyvpn-controller/current/node_modules/pg/lib/index.js'; const c=new pg.Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:2500}); try{await c.connect();const r=await c.query('SELECT current_user AS role');if(r.rows[0]?.role!=="+repr(role)+")throw Error('wrong role');}finally{await c.end();}",env=env)


def active(name):
    return subprocess.run(["systemctl","is-active","--quiet",name],capture_output=True,timeout=8).returncode==0


def stage(src):
    check(os.geteuid()==0,"root_required")
    check(preflight()=="applied","fi_schema_not_staged")
    for path in (ROOT,ROOT/"config",ROOT/"approvals"):
        private_dir(path)
    for name,digest in (("controller-public.spki",CONTROLLER_PIN),("fi-node-public.spki",NODE_PIN)):
        check(hashlib.sha256(private_file(ROOT/name,100)).hexdigest()==digest,"trust_pin_mismatch")
    private_file(ROOT/"controller-signing-key.pem",8192)
    check(call(str(RUNTIME/"bin/node"),"-v").strip()==b"v22.23.5","unexpected_node_runtime")
    private_dir(src)
    private_dir(DEST,create=True);private_dir(STATE,create=True)
    # Install an isolated immutable source tree. Existing AWG runtime is untouched.
    for name in MODULES:
        exact_file(DEST/name,private_file(src/name,100000))
    exact_file(DEST/"package.json",b'{"type":"module"}\n')
    for mode in MODES:
        check(not active(unit(mode)),"existing_worker_active")
        for base in (Path("/etc/systemd/system"),Path("/run/systemd/system"),Path("/usr/lib/systemd/system"),Path("/lib/systemd/system")):
            drop=base/(unit(mode)+".d")
            check(not drop.exists() and not drop.is_symlink(),"existing_unit_override")
            if base!=UNITDIR:
                path=base/unit(mode)
                check(not path.exists() and not path.is_symlink(),"existing_foreign_unit")
        exact_file(UNITDIR/unit(mode),private_file(src/unit(mode),10000))
        create_role(mode)
    call(str(RUNTIME/"bin/node"),"--check",str(DEST/MODULES[0]))
    call("systemd-analyze","verify",*(str(UNITDIR/unit(m)) for m in MODES))
    call("systemctl","daemon-reload")
    marker=ROOT/"approvals/fi-dns-private.enable"
    check(not marker.exists() and not marker.is_symlink(),"unexpected_private_approval")
    # Start only the private controller, with the DB gate OFF and no grants.
    exclusive(marker,b"private-fi-dns-stage-v1\n")
    started=[]
    try:
        for mode in MODES:
            started.append(mode)
            call("systemctl","start",unit(mode))
        import time
        for _ in range(20):
            if all(active(unit(m)) for m in MODES) and (STATE/"snapshot.json").is_file():
                break
            time.sleep(0.5)
        check(all(active(unit(m)) for m in MODES),"controller_service_not_active")
        import json
        snapshot=json.loads(private_file(STATE/"snapshot.json",700000))
        check(snapshot.get("grants")==[] and snapshot.get("nodeId")=="fi-test-01","unexpected_nonempty_policy")
        check(psql("SELECT NOT enabled FROM public.fi_dns_meter_gate WHERE singleton;")=="t","fi_gate_not_off")
        print("FI_DNS_CONTROLLER_SERVICES_ACTIVE=true;FI_SIGNED_EMPTY_SNAPSHOT_READY=true;FI_GATE_OFF=true")
    except BaseException:
        for mode in started:
            subprocess.run(["systemctl","stop",unit(mode)],capture_output=True,timeout=15)
        marker.unlink(missing_ok=True)
        raise


if __name__=="__main__":
    try:
        os.umask(0o077)
        check(len(sys.argv)==2 and re.fullmatch(r"/run/fi-dns-controller-[0-9]+-[0-9]+",sys.argv[1]),"invalid_stage")
        fd=os.open("/run/lock/mnebyvpn-fi-dns-controller-stage.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            stage(Path(sys.argv[1]))
        finally:
            os.close(fd)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        label=str(exc) if isinstance(exc,RuntimeError) and re.fullmatch("[a-z0-9_]+",str(exc)) else "stage_failed"
        print("FI_DNS_CONTROLLER_STAGE_BLOCKED="+label,file=sys.stderr)
        raise SystemExit(2)
