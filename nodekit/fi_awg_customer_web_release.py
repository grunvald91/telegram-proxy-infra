#!/usr/bin/env python3
"""RU188: publish native FI217 AWG to authenticated VPN subscribers.

Release is owner-approved, but it must point to the exact successful LIVE
FI217 external E2E proof and pinned public server material. Retains existing
VLESS, billing, trials and all unrelated containers. Canary first; rollback
restores the previous website image, environment and release flag.
"""
from __future__ import annotations
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from urllib import request,error

ROOT=Path("/opt/mnebyvpn")
PUBLIC=ROOT/"public"
WEB_ENV=PUBLIC/"web.env"
BACKUP=PUBLIC/".fi217-awg-web-env-pre-release"
WEB_NAME="mnebyvpn-public-web"
CANARY="mnebyvpn-fi-awg-release-canary"
LOCK=Path("/run/lock/mnebyvpn-public-prepare.lock")
FI="fi-test-01"
FI_PUB="fi.mnebyvpn.site"
FIELDS={
    "WEB_NETWORK_PROVISIONING_VERIFIED":"yes",
    "WEB_FI_AWG_REGISTRATION_ENABLED":"yes",
    "WEB_FI_AWG_MATERIAL_ENABLED":"yes",
}
class Blocked(ValueError):pass

def cmd(argv:list[str],*,data:str|None=None,check:bool=True,timeout:int=30)->subprocess.CompletedProcess:
    return subprocess.run(argv,input=data,stdin=subprocess.DEVNULL if data is None else None,
                          capture_output=True,text=True,check=check,timeout=timeout)

def sql(statement:str)->str:
    result=cmd(["docker","exec","-i","mnebyvpn-stage-postgres",
        "psql","-X","-q","-A","-t","-v","ON_ERROR_STOP=1",
        "-U","mnebyvpn_stage","-d","mnebyvpn_stage"],data=statement,timeout=20)
    return result.stdout.strip()

def valid_key(value:str)->bool:
    try:
        if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=",value):
            return False
        raw=base64.b64decode(value,validate=True)
        return len(raw)==32 and base64.b64encode(raw).decode()==value and any(raw)
    except (ValueError,base64.binascii.Error):return False

def trusted(path:Path,max_bytes:int=70000)->bytes:
    if path.is_symlink() or not path.is_file():raise Blocked("missing trusted file")
    s=path.stat()
    if (s.st_uid!=0 or not stat.S_ISREG(s.st_mode) or
        s.st_mode&0o077 or s.st_nlink!=1 or not 1<=s.st_size<=max_bytes):
        raise Blocked("untrusted root file")
    return path.read_bytes()

def material(path:Path)->dict:
    raw=trusted(path,4096)
    data=json.loads(raw)
    if (not isinstance(data,dict) or data.get("nodeId")!=FI or
        data.get("hostname")!=FI_PUB or data.get("port")!=51821 or
        data.get("clientIp")!="10.73.91.253" or
        not valid_key(data.get("serverPublicKey")) or
        not valid_key(data.get("headerKey"))):
        raise Blocked("untrusted FI material")
    return data

def read_env(raw:bytes)->tuple[list[str],dict[str,str]]:
    try: lines=raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:raise Blocked("web env non UTF-8")
    out={}
    for line in lines:
        if line.startswith("#") or not line:continue
        key,sep,value=line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}",key) or key in out:
            raise Blocked("invalid or duplicate env key")
        out[key]=value
    if (out.get("MNEBYVPN_ENV")!="production" or
        out.get("WEB_BASE_URL")!="https://mnebyvpn.site" or
        out.get("WEB_EMAIL_LOGIN_ENABLED")!="yes" or
        out.get("WEB_RELEASE_APPROVED")!="yes"):
        raise Blocked("production website or authenticated login unready")
    return lines,out

def updated_env(raw:bytes,pub:str,header:str)->bytes:
    lines,old=read_env(raw)
    changes=dict(FIELDS,
                 WEB_FI_AWG_SERVER_PUBLIC_KEY=pub,
                 WEB_FI_AWG_HEADER_PROTECTION_KEY=header)
    for key,value in changes.items():
        if key not in old:lines.append(key+"="+value)
    return ("\n".join([
        line.split("=",1)[0]+"="+changes[line.split("=",1)[0]]
        if line.partition("=")[0] in changes else line
        for line in lines
    ])+"\n").encode()

def site_info()->tuple[str,dict]:
    doc=json.loads(cmd(["docker","inspect",WEB_NAME]).stdout)
    if not isinstance(doc,list) or len(doc)!=1:raise Blocked("unknown public site")
    item=doc[0]
    if (item.get("Name")!="/"+WEB_NAME or
        item.get("State",{}).get("Running") is not True or
        item.get("HostConfig",{}).get("NetworkMode")!="host" or
        item.get("HostConfig",{}).get("ReadonlyRootfs") is not True or
        item.get("Config",{}).get("User")!="1000:1000" or
        item.get("HostConfig",{}).get("Privileged") is True):
        raise Blocked("public site container contract changed")
    image=item.get("Image")
    if not isinstance(image,str) or not re.fullmatch(r"sha256:[0-9a-f]{64}",image):
        raise Blocked("unpinned public site image")
    # Old public image must already contain the authenticated setup route.
    check=cmd(["docker","exec",WEB_NAME,"sh","-c",
               "grep -q fiAwgRegistrationAvailable /srv/mnebyvpn/apps/web/src/server.ts"],
              check=False,timeout=8)
    if check.returncode:raise Blocked("deployed website code lacks FI AWG registration")
    return image,item

def active(unit:str)->bool:
    return cmd(["systemctl","is-active","--quiet",unit],check=False).returncode==0

def pool_ready(pub:str)->None:
    if not active("mnebyvpn-awg-delivery.service"):
        raise Blocked("RU188 worker not active")
    query=(
      "SELECT (SELECT CASE WHEN state='verified' "
      "AND verified_at>clock_timestamp()-interval '1 hour' "
      "AND verified_at<=clock_timestamp()+interval '30 seconds' "
      "AND external_e2e_proof_sha256 ~ '^[a-f0-9]{64}$' "
      "AND server_public_key='"+pub+"' "
      "AND endpoint_host='fi.mnebyvpn.site' AND listen_port=51821 "
      "THEN 'ready' ELSE 'blocked' END "
      "FROM public.vpn_awg_node_pools WHERE node_id='fi-test-01'),"
      "(SELECT status FROM public.vpn_node_enrollment_inventory "
      "WHERE node_id='fi-test-01'),"
      "(SELECT enabled::text FROM public.vpn_release_flags "
      "WHERE feature='vpn_awg_clients');"
    )
    status=sql(query)
    if status not in ("ready|enrolled|false","ready|enrolled|true"):
        raise Blocked("fresh signed external test or enrollment missing")

def release_flag(enable:bool,pub:str)->None:
    # Rechecks one-hour external E2E proof in SAME transaction as the switch.
    mode="true" if enable else "false"
    if enable:
        statement=f"""
BEGIN;
DO $release$
DECLARE n integer;
BEGIN
 IF NOT EXISTS(
 SELECT 1 FROM public.vpn_awg_node_pools
 WHERE node_id='fi-test-01' AND endpoint_host='fi.mnebyvpn.site'
   AND state='verified' AND server_public_key='{pub}'
   AND verified_at>clock_timestamp()-interval '1 hour'
   AND verified_at<=clock_timestamp()+interval '30 seconds'
   AND external_e2e_proof_sha256 ~ '^[a-f0-9]{{64}}$'
 ) THEN RAISE EXCEPTION 'FI217 external E2E proof stale'; END IF;
 UPDATE public.vpn_release_flags SET enabled=true
 WHERE feature='vpn_awg_clients' AND enabled=false;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n!=1 THEN RAISE EXCEPTION 'release flag has changed'; END IF;
END $release$;
COMMIT;
"""
    else:
        statement="""BEGIN;
UPDATE public.vpn_release_flags SET enabled=false
WHERE feature='vpn_awg_clients' AND enabled=true;
COMMIT;"""
    sql(statement)

def write_atomic(path:Path,data:bytes)->None:
    fd,tmp=tempfile.mkstemp(prefix=".fi-awg-site-",dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(tmp,path)
    finally:Path(tmp).unlink(missing_ok=True)

def launch(image:str,name:str,port:int,web_file:Path,old:dict,*,temporary:bool)->None:
    argv=["docker","run","-d"]
    if temporary:argv.append("--rm")
    else:argv+=["--restart","unless-stopped"]
    argv+=["--name",name,"--network","host","--user","1000:1000",
           "--read-only","--tmpfs","/tmp:rw,nosuid,nodev,size=32m",
           "--cap-drop","ALL","--security-opt","no-new-privileges",
           "--pids-limit","96","--memory","300m","--cpus","0.4"]
    env=read_env(trusted(web_file))[1]
    argv+=["--env-file",str(web_file),
           "--env-file",str(ROOT/"bot/worker.env"),
           "--env-file",str(PUBLIC/"subscription-db.env")]
    if env.get("WEB_EMAIL_LOGIN_ENABLED")=="yes":
        argv+=["--env-file",str(PUBLIC/"auth-db.env")]
    if (env.get("WEB_CHECKOUT_ENABLED")=="1" or
        env.get("WEB_YOOKASSA_ENABLED")=="yes" or
        env.get("WEB_PRODAMUS_WEBHOOK_ENABLED")=="yes"):
        argv+=["--env-file",str(PUBLIC/"billing-db.env")]
        if (PUBLIC/"prodamus.env").exists():
            argv+=["--env-file",str(PUBLIC/"prodamus.env")]
        if env.get("WEB_YOOKASSA_ENABLED")=="yes":
            argv+=["--env-file",str(PUBLIC/"yookassa.env")]
    if (PUBLIC/"web-proxy.env").exists():
        argv+=["--env-file",str(PUBLIC/"web-proxy.env")]
    argv+=["-e","WEB_PORT="+str(port),image]
    cmd(argv,timeout=30)

def http(path:str,port:int)->int:
    try:
        with request.urlopen("http://127.0.0.1:"+str(port)+path,timeout=5) as response:
            return response.status
    except error.HTTPError as exc:return exc.code
    except (OSError,ValueError):return 0

def healthy(port:int)->None:
    for _ in range(30):
        if http("/healthz",port)==200:break
        time.sleep(1)
    if (http("/healthz",port)!=200 or http("/awg/setup",port)!=200 or
        http("/awg-setup.js",port)!=200):
        raise Blocked("public FI device setup not available")
    if http("/api/auth/options",port)!=200:
        raise Blocked("login options missing")

def release(path:Path)->str:
    if os.geteuid()!=0:raise Blocked("root required")
    addr=cmd(["ip","-o","-4","addr","show"]).stdout
    if "188.120.254.223/" not in addr:raise Blocked("not RU188")
    payload=material(path)
    pub,header=payload["serverPublicKey"],payload["headerKey"]
    pool_ready(pub)
    before=trusted(WEB_ENV)
    new=updated_env(before,pub,header)
    state=sql("SELECT enabled::text FROM public.vpn_release_flags WHERE feature='vpn_awg_clients';")
    if state=="true" and new==before and http("/awg/setup",8792)==200:
        return "ALREADY_PUBLIC"
    if state!="false":raise Blocked("partial or unexpected release state")
    image,old=site_info()
    # Scope to known single-owner Docker resource contract.
    candidate=PUBLIC/".fi-awg-next-web.env"
    if candidate.exists() or candidate.is_symlink():
        raise Blocked("stale staged website env")
    write_atomic(candidate,new)
    flag=False
    changed=False
    stopped=False
    backup_created=False
    try:
        # Run a separate localhost canary before touching the real site.
        if cmd(["docker","inspect",CANARY],check=False).returncode==0:
            raise Blocked("canary name occupied")
        port=18793
        for value in (18793,18794,18795,28793,28794):
            if cmd(["ss","-H","-lnt"],timeout=8).stdout.find(":"+str(value))<0:
                port=value;break
        launch(image,CANARY,port,candidate,old,temporary=True)
        healthy(port)
        cmd(["docker","stop","-t","4",CANARY],timeout=12)
        release_flag(True,pub);flag=True
        if BACKUP.exists() or BACKUP.is_symlink():
            raise Blocked("unexpected prior AWG web backup")
        with BACKUP.open("xb") as file:
            os.fchmod(file.fileno(),0o600)
            file.write(before);file.flush();os.fsync(file.fileno())
        backup_created=True
        write_atomic(WEB_ENV,new);changed=True
        cmd(["docker","stop","-t","12",WEB_NAME],timeout=22)
        stopped=True
        cmd(["docker","rm",WEB_NAME],timeout=15)
        launch(image,WEB_NAME,8792,WEB_ENV,old,temporary=False)
        healthy(8792)
        if cmd(["docker","inspect","-f","{{.State.Running}}",WEB_NAME]).stdout.strip()!="true":
            raise Blocked("new web container inactive")
        print("FI_AWG_CUSTOMER=PUBLIC;WEB_SETUP=200;FI_POOL=FRESH;RU_WORKER=ACTIVE;AWG_RELEASE=true")
        return "PUBLIC"
    except BaseException:
        cmd(["docker","rm","-f",CANARY],check=False,timeout=14)
        if flag:release_flag(False,pub)
        if changed:write_atomic(WEB_ENV,before)
        if backup_created and trusted(BACKUP)==before:
            BACKUP.unlink()
        if stopped:
            cmd(["docker","rm","-f",WEB_NAME],check=False,timeout=14)
            launch(image,WEB_NAME,8792,WEB_ENV,old,temporary=False)
            healthy_before= http("/healthz",8792)
            if healthy_before!=200:raise Blocked("website rollback failed")
        raise
    finally:
        candidate.unlink(missing_ok=True)

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("release",),required=True)
    p.add_argument("--material",type=Path,required=True)
    args=p.parse_args()
    try:
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=release(args.material)
            print("FI_AWG_CUSTOMER_RELEASE="+result)
            return 0
        finally:os.close(fd)
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
        print("FI_AWG_CUSTOMER_RELEASE=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
