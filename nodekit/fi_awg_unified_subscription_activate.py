#!/usr/bin/env python3
"""RU188 guarded upgrade of the existing FI217 AWG delivery and INCY feed.

Keeps existing HTTPS /sub tokens, canonical entitlements, VLESS credentials,
old proven FI217 peer grants, bot, DNS and proxies. All private signing keys
stay on RU188. The NEW 32-byte root subscriber seed is generated locally
once and never printed, copied to GitHub, or returned by the workflow.
"""
from __future__ import annotations
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import fi_awg_customer_web_release as web

RU="188.120.254.223"
CURRENT="446c331249085adb6536e3d9913fb4b68abf6cd7"
NEW="eec5b86c62b6c58bdbda8735c7e75fd9f38fd859"
RELEASES=Path("/opt/mnebyvpn-controller/awg-worker-releases")
OLD=RELEASES/CURRENT
NEW_RELEASE=RELEASES/NEW
UNIT="mnebyvpn-awg-delivery.service"
OVERRIDE=Path("/etc/systemd/system/mnebyvpn-awg-delivery.service.d/90-isolated-awg-worker.conf")
WORKER_ENV=Path("/root/mnebyvpn-controller/config/awg-delivery.env")
SEED=Path("/root/mnebyvpn-controller/config/awg-subscription-seed.hex")
LOCK=Path("/run/lock/mnebyvpn-awg-subscription-cutover.lock")
PUBLIC_ENV=web.WEB_ENV
SOURCE={
 "apps/service/src/awg-controller-delivery-worker.ts":"ca548e7a05ede7109b9dfcb8e0a92399af37f5e2",
 "packages/provisioning/src/awg-device-registration-worker.ts":"e3f0be01038942b4e0785e7e9b8d355480f2dbed",
 "packages/provisioning/src/awg-in-subscription.ts":"fb617bd3886240ffe24694e028f2f2df83783581",
 "packages/provisioning/src/awg-subscriber-material.ts":"2152b16f2f297b80c8749043f5068034c4b93e02",
 "packages/provisioning/src/awg-trusted-ssh-delivery.ts":"516706e898f6e59599172ce3c65d9f2295a4876e",
 "packages/provisioning/src/awg-offline-maintenance.ts":"e8829944ca4d27e1d8b8679efa681f6bb3abe373",
 "packages/provisioning/src/awg-controller-grants.ts":"26723d9cf9b1b4a04103251ec53777fa5af9d21e",
 "packages/provisioning/src/awg-controller-outbox.ts":"0b1c1f0906a0a11be8a1c466fa5eb173bd39906b",
}
WORKER=Path("apps/service/src/awg-controller-delivery-worker.ts")
HEX=re.compile(r"[a-f0-9]{64}\Z")
KEY="AWG_INCY_SUBSCRIPTION_SEED"

class Blocked(ValueError):pass

def cmd(argv:list[str],*,timeout:int=25,check:bool=True):
    return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,timeout=timeout,check=check)

def active()->bool:
    return cmd(["systemctl","is-active","--quiet",UNIT],check=False).returncode==0

def show(prop:str)->str:
    return cmd(["systemctl","show","-p",prop,"--value",UNIT]).stdout.strip()

def trusted(path:Path,limit:int=125000)->bytes:
    if path.is_symlink() or not path.is_file():raise Blocked("missing protected config")
    s=path.stat()
    if s.st_uid!=0 or s.st_mode&0o077 or s.st_nlink!=1 or s.st_size<1 or s.st_size>limit:
        raise Blocked("untrusted protected config")
    return path.read_bytes()

def root_systemd_dropin(path:Path)->bytes:
    # Existing signed systemd cutover explicitly installs root-owned 0644
    # drop-ins; they contain paths but NEVER secrets. A protected 0600 env
    # reader must not be reused for public systemd unit files.
    if path.is_symlink() or not path.is_file():
        raise Blocked("systemd unit override missing")
    meta=path.stat()
    if (meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o644 or
        meta.st_nlink!=1 or not 1<=meta.st_size<=8192):
        raise Blocked("systemd unit override ownership/mode mismatch")
    return path.read_bytes()


def put_systemd_dropin(data:bytes)->None:
    # Preserve the exact reviewed 0644 mode throughout the atomic cutover.
    if not data or len(data)>8192:raise Blocked("invalid systemd dropin length")
    if OVERRIDE.is_symlink():raise Blocked("unit override symlink")
    fd,tmp=tempfile.mkstemp(prefix=".mnebyvpn-awg-",dir=OVERRIDE.parent)
    try:
        os.fchmod(fd,0o644)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp,OVERRIDE)
        folder=os.open(OVERRIDE.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(folder)
        finally:os.close(folder)
    finally:Path(tmp).unlink(missing_ok=True)


def git_blob(raw:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def staged(stage:Path)->dict[Path,bytes]:
    # Emit only fixed booleans and permission bits. No path, key, or user data.
    stage_name_ok=bool(re.fullmatch(
        r"/run/fi-awg-subscription\.[A-Za-z0-9]{8}",str(stage)))
    stage_type_ok=stage.is_absolute() and not stage.is_symlink() and stage.is_dir()
    stage_meta=stage.stat() if stage_type_ok else None
    stage_uid_ok=stage_meta is not None and stage_meta.st_uid==0
    stage_mode_ok=stage_meta is not None and stat.S_IMODE(stage_meta.st_mode)==0o700
    print("FI_AWG_STAGE_META=NAME:"+("YES" if stage_name_ok else "NO")+
          ";TYPE:"+("YES" if stage_type_ok else "NO")+
          ";ROOT:"+("YES" if stage_uid_ok else "NO")+
          ";MODE700:"+("YES" if stage_mode_ok else "NO"),
          flush=True)
    if not (stage_name_ok and stage_type_ok and stage_uid_ok and stage_mode_ok):
        raise Blocked("untrusted source stage")
    result={}
    for relative,sha in SOURCE.items():
        file=stage/relative
        payload=trusted(file,100000)
        if git_blob(payload)!=sha or not payload.endswith(b"\n"):
            raise Blocked("unapproved FI subscription source")
        result[Path(relative)]=payload
    return result

def preflight()->bytes:
    print('FI_AWG_PRECHECK=HOST_BEGIN',flush=True)
    if os.geteuid()!=0 or RU+"/" not in cmd(["ip","-o","-4","addr","show"]).stdout:
        raise Blocked("not RU188 root")
    if not active() or show("SubState")!="running" or int(show("MainPID"))<=1:
        raise Blocked("existing signed delivery worker inactive")
    if show("WorkingDirectory")!=str(OLD):
        raise Blocked("unapproved existing worker revision")
    print("FI_AWG_PRECHECK=WORKER_APPROVED",flush=True)
    if show("NeedDaemonReload")!="no":raise Blocked("worker unit drift")
    raw=root_systemd_dropin(OVERRIDE)
    if (raw.count(str(OLD).encode())!=2 or
        raw.count(b"WorkingDirectory=")!=1 or
        raw.count(b"ExecStart=")!=2 or
        b"/opt/mnebyvpn-controller/current/bin/node" not in raw):
        raise Blocked("existing systemd drop-in changed")
    print("FI_AWG_PRECHECK=DROPIN_APPROVED",flush=True)
    if not (OLD/"node_modules/pg/package.json").is_file() or (OLD/"node_modules").is_symlink():
        raise Blocked("previous pinned pg dependency not verified")
    print("FI_AWG_PRECHECK=PG_APPROVED",flush=True)
    worker=trusted(WORKER_ENV)
    if b"MNEBYVPN_AWG_DELIVERY_WORKER=enabled" not in worker:
        raise Blocked("existing worker env not approved")
    print("FI_AWG_PRECHECK=WORKER_ENV_APPROVED",flush=True)
    original=trusted(PUBLIC_ENV)
    public=web.read_env(original)[1]
    if public.get("WEB_FI_AWG_MATERIAL_ENABLED")!="yes":
        raise Blocked("FI native signed material not enabled")
    if (public.get("WEB_FI_AWG_REGISTRATION_ENABLED")!="yes" or
        public.get("WEB_NETWORK_PROVISIONING_VERIFIED")!="yes"):
        raise Blocked("FI public enrollment is not ready")
    print("FI_AWG_PRECHECK=WEB_ENV_APPROVED",flush=True)
    image,_=web.site_info()
    # The running image must already be from the new, tested Mnebyvpn SHA.
    proof=cmd(["docker","exec",web.WEB_NAME,"sh","-c",
      "grep -Fq awgInSubscriptionEnabled /srv/mnebyvpn/apps/web/src/server.ts"],
      check=False,timeout=10)
    if proof.returncode!=0:raise Blocked("public site has not deployed mixed profile code")
    print("FI_AWG_PRECHECK=WEB_IMAGE_APPROVED",flush=True)
    gateway=web.sql(
      "SELECT CASE WHEN to_regprocedure("+
      "'public.awg_controller_enqueue_fi_subscription(uuid,text,bigint)') "+
      "IS NOT NULL THEN 'READY' ELSE 'MISSING' END;")
    if gateway!="READY":
        raise Blocked("RU188 scoped AWG subscription enqueue migration not installed")
    print("FI_AWG_PRECHECK=DB_GATEWAY_APPROVED",flush=True)
    release=cmd(["docker","exec","mnebyvpn-stage-postgres","psql",
        "-X","-q","-A","-t","-v","ON_ERROR_STOP=1",
        "-U","mnebyvpn_stage","-d","mnebyvpn_stage",
        "-c","SELECT enabled::text FROM public.vpn_release_flags WHERE feature='vpn_awg_clients'"],
        timeout=18).stdout.strip()
    if release!="true":raise Blocked("canonical FI client release is disabled")
    print("FI_AWG_PRECHECK=DB_RELEASE_APPROVED",flush=True)
    return raw

def stage_release(stage:Path,blobs:dict[Path,bytes])->None:
    print("FI_AWG_SUB_STAGE=RELEASE_ROOT_BEGIN",flush=True)
    if not RELEASES.is_dir() or RELEASES.is_symlink() or RELEASES.stat().st_uid!=0:
        raise Blocked("untrusted release root")
    print("FI_AWG_SUB_STAGE=RELEASE_ROOT_APPROVED",flush=True)
    if NEW_RELEASE.exists() or NEW_RELEASE.is_symlink():
        if NEW_RELEASE.is_symlink() or NEW_RELEASE.stat().st_uid!=0:
            raise Blocked("untrusted candidate directory")
        for rel,payload in blobs.items():
            if trusted(NEW_RELEASE/rel,100000)!=payload:
                raise Blocked("existing candidate differs")
        if not (NEW_RELEASE/"node_modules/pg/package.json").is_file():
            raise Blocked("incomplete existing module graph")
        return
    print("FI_AWG_SUB_STAGE=NEW_RELEASE_CREATE",flush=True)
    NEW_RELEASE.mkdir(mode=0o700)
    try:
        for rel,payload in blobs.items():
            path=NEW_RELEASE/rel
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(payload)
            path.chmod(0o600)
        print("FI_AWG_SUB_STAGE=SOURCE_COPIED",flush=True)
        shutil.copytree(OLD/"node_modules",NEW_RELEASE/"node_modules",
                        symlinks=False,dirs_exist_ok=False)
        print("FI_AWG_SUB_STAGE=PG_DEPENDENCIES_COPIED",flush=True)
        cmd(["/opt/mnebyvpn-controller/current/bin/node",
             "--experimental-strip-types","--input-type=module","-e",
             "await import('file://"+str(NEW_RELEASE/WORKER)+"')"],
             timeout=60)
    except BaseException:
        # A partially staged candidate is never selected as the effective unit.
        shutil.rmtree(NEW_RELEASE,ignore_errors=True)
        raise

def subscription_seed()->str:
    if SEED.exists() or SEED.is_symlink():
        raw=trusted(SEED,128)
        value=raw.decode("ascii").strip()
        if not HEX.fullmatch(value) or value=="0"*64:
            raise Blocked("previous subscriber seed invalid")
        return value
    fd=os.open(SEED,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    value=secrets.token_hex(32)
    with os.fdopen(fd,"wb") as stream:
        stream.write((value+"\n").encode());stream.flush();os.fsync(stream.fileno())
    if trusted(SEED,128)!=(value+"\n").encode():
        raise Blocked("subscriber seed not durable")
    return value

def replace_env(raw:bytes,changes:dict[str,str])->bytes:
    try:lines=raw.decode("utf-8").splitlines()
    except UnicodeError:raise Blocked("invalid env encoding")
    seen=set()
    for line in lines:
        if not line or line.startswith("#"):continue
        name,sep,value=line.partition("=")
        if not sep or name in seen or not re.fullmatch("[A-Z][A-Z0-9_]{2,80}",name):
            raise Blocked("unexpected live environment")
        seen.add(name)
        if name in changes and value!=changes[name]:
            raise Blocked("existing subscriber identity mismatch; do not rotate")
    for name,value in changes.items():
        if name not in seen:lines.append(name+"="+value)
    return ("\n".join(lines)+"\n").encode()

def activate(stage:Path)->None:
    old_override=preflight()
    print("FI_AWG_SUB_STAGE=PINNED_INPUTS_BEGIN",flush=True)
    blobs=staged(stage)
    print("FI_AWG_SUB_STAGE=PINNED_INPUTS_VERIFIED",flush=True)
    stage_release(stage,blobs)
    print("FI_AWG_SUB_STAGE=IMMUTABLE_RELEASE_VERIFIED",flush=True)
    old_worker=trusted(WORKER_ENV)
    old_web=trusted(PUBLIC_ENV)
    value=subscription_seed()
    worker_next=replace_env(old_worker,{KEY:value})
    web_next=replace_env(old_web,{KEY:value,
        "WEB_FI_AWG_IN_SUBSCRIPTION_ENABLED":"yes"})
    new_override=old_override.replace(str(OLD).encode(),str(NEW_RELEASE).encode())
    if new_override.count(str(NEW_RELEASE).encode())!=2:
        raise Blocked("unknown new worker override")
    changed_unit=False
    changed_worker_env=False
    changed_web_env=False
    changed_web_container=False
    image,_=web.site_info()
    try:
        # Worker changes before website can advertise any previously ungranted FI peers.
        web.write_atomic(WORKER_ENV,worker_next);changed_worker_env=True
        put_systemd_dropin(new_override);changed_unit=True
        cmd(["systemctl","daemon-reload"])
        cmd(["systemctl","restart",UNIT],timeout=38)
        for _ in range(8):
            if active() and show("WorkingDirectory")==str(NEW_RELEASE):
                break
            time.sleep(1)
        if not active() or show("WorkingDirectory")!=str(NEW_RELEASE):
            raise Blocked("new controller worker did not start")
        # Safe canary using the currently deployed verified web image.
        candidate=Path("/opt/mnebyvpn/public/.fi217-subscription-next.env")
        if candidate.exists() or candidate.is_symlink():
            raise Blocked("stale website configuration candidate")
        web.write_atomic(candidate,web_next)
        try:
            name="mnebyvpn-fi-sub-canary"
            if cmd(["docker","inspect",name],check=False).returncode==0:
                raise Blocked("web canary name already used")
            web.launch(image,name,18797,candidate,{},temporary=True)
            web.healthy(18797)
        finally:
            cmd(["docker","rm","-f","mnebyvpn-fi-sub-canary"],check=False,timeout=15)
            candidate.unlink(missing_ok=True)
        web.write_atomic(PUBLIC_ENV,web_next);changed_web_env=True
        # Mark rollback needed BEFORE stopping: a partial stop or failed
        # removal must still restore the old website, never leave it off.
        changed_web_container=True
        cmd(["docker","stop","-t","12",web.WEB_NAME],timeout=22)
        cmd(["docker","rm",web.WEB_NAME],timeout=15)
        web.launch(image,web.WEB_NAME,8792,PUBLIC_ENV,{},temporary=False)
        web.healthy(8792)
        if not active() or show("WorkingDirectory")!=str(NEW_RELEASE):
            raise Blocked("AWG controller worker no longer active")
        print("FI_AWG_UNIFIED_SUBSCRIPTION=ENABLED;RU188_WORKER=ACTIVE;WEB=ACTIVE;KEYS=PROTECTED;CUSTOMER_RELEASE=UNCHANGED")
    except BaseException:
        # Preserve all preexisting customer grants, billing and public token rows.
        if changed_web_env:web.write_atomic(PUBLIC_ENV,old_web)
        if changed_web_container:
            cmd(["docker","rm","-f",web.WEB_NAME],check=False,timeout=15)
            web.launch(image,web.WEB_NAME,8792,PUBLIC_ENV,{},temporary=False)
            web.healthy(8792)
        if changed_unit:put_systemd_dropin(old_override)
        if changed_worker_env:web.write_atomic(WORKER_ENV,old_worker)
        if changed_unit:
            cmd(["systemctl","daemon-reload"])
            cmd(["systemctl","restart",UNIT],timeout=38)
        if not active() or show("WorkingDirectory")!=str(OLD):
            raise Blocked("worker rollback incomplete")
        raise

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--stage",type=Path,required=True)
    parser.add_argument("--mode",choices=("diagnose","activate"),default="activate")
    args=parser.parse_args()
    try:
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            meta=os.fstat(fd)
            if meta.st_uid!=0 or meta.st_mode&0o077 or not stat.S_ISREG(meta.st_mode):
                raise Blocked("untrusted activation lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.mode=="diagnose":
                preflight()
                staged(args.stage)
                print("FI_AWG_SUB_DIAG=READY;ACTIVATION_PERFORMED=false",flush=True)
            else:
                activate(args.stage)
        finally:os.close(fd)
        return 0
    except Blocked as exc:
        # Small closed vocabulary: never emit arbitrary filesystem paths,
        # credentials, SQL or subprocess diagnostics into GitHub Actions.
        reasons={
            "untrusted source stage":"UNTRUSTED_STAGE",
            "unapproved FI subscription source":"SOURCE_PIN_MISMATCH",
            "untrusted release root":"RELEASE_ROOT",
            "untrusted candidate directory":"EXISTING_RELEASE",
            "existing candidate differs":"CANDIDATE_DRIFT",
            "incomplete existing module graph":"PG_GRAPH",
            "untrusted protected config":"UNTRUSTED_FILE",
            "missing protected config":"FILE_MISSING",
            "untrusted activation lock":"LOCK",
        }
        print("FI_AWG_SUB_BLOCK_REASON="+reasons.get(str(exc),"OTHER_REFUSAL"),file=sys.stderr)
        print("FI_AWG_UNIFIED_SUBSCRIPTION=BLOCKED",file=sys.stderr)
        return 2
    except (OSError,ValueError,TypeError,UnicodeError,subprocess.SubprocessError):
        print("FI_AWG_UNIFIED_SUBSCRIPTION=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
