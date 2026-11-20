#!/usr/bin/env python3
"""FI217 signed production AWG 3.1 service activation; no client publication.

Driven only from pinned GitHub Actions, with controller-signed exact node and
binary/config identity. Any incomplete activation stops the new AWG stack and
restores dormant manifests, never touches unrelated tunnels or client flags.
"""
from __future__ import annotations
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from install_components import node_ready, safe_manifest
from awg_lifecycle import AWG_BIN, validate as validate_awg, unit_name, active_unit
import awg_egress
import install_awg_watchdog
from fi_awg_production_policy import admit, verify_approval, canonical_key
import fi_awg_signed_canary as trust

NODE="fi-test-01"
ROOT=Path("/var/lib/mnebyvpn-nodekit")
DATA=ROOT/NODE
AWG=DATA/"amneziawg"
APP=Path("/opt/mnebyvpn-nodekit")
BACK=DATA/"production-backup"
APPROVAL=AWG/"production-approval.json"
LOCK=Path("/run/lock/mnebyvpn-fi-awg-production.lock")
AWG_SERVICE="mnebyvpn-nodekit-awg@fi-test-01.service"
WATCHDOG="mnebyvpn-nodekit-awg-watchdog@fi-test-01.service"
EGRESS="mnebyvpn-nodekit-awg-egress@fi-test-01.service"
UNITS=(AWG_SERVICE,WATCHDOG,EGRESS)
FILES=("manifest.json","amneziawg/manifest.json")
SOURCE_SHA={
    "awg_lifecycle.py":"c58d54c0f636645ef1bdedb351d97f9224c79e83",
    "install_components.py":"68d9c578c7690a05fbc9c6024176261762e37896",
    "fi_awg_production_policy.py":"c31ae46df590713a0daf26f79f3bc4916961c22a",
    "awg_egress.py":"4a32a116f1e2c5c967806a4cdf0aee07f1a32985",
}
class Blocked(ValueError):pass

def run(argv:list[str],timeout:int=30,check:bool=True)->subprocess.CompletedProcess:
    return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,timeout=timeout,check=check)

def protected(path:Path,limit:int=100000)->bytes:
    return trust.protected(path,limit)

def require_identity()->None:
    if not trust.is_host(trust.FI_IP):raise Blocked("wrong FI217 host")
    trust.pinned_spki(DATA/"controller-access.spki",trust.CONTROLLER_SHA)
    trust.pinned_spki(DATA/"identity/node-public.spki",trust.NODE_SHA)
    for filename,sha in SOURCE_SHA.items():
        raw=protected(APP/filename,200000)
        if hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()!=sha:
            raise Blocked("unknown production source")

def state()->str:
    manifest=safe_manifest(DATA/"manifest.json")
    awg=safe_manifest(AWG/"manifest.json")
    if manifest.get("node_id")!=NODE or manifest.get("advertise_host")!=trust.HOST:
        raise Blocked("node identity")
    if awg.get("node_id")!=NODE:return "UNKNOWN"
    staged=(manifest.get("state")=="testing" and
            manifest.get("activation_enabled") is False and
            manifest.get("registration_enabled") is False and
            awg.get("state")=="staged" and
            awg.get("activation_enabled") is False and
            awg.get("peers_enabled") is False and
            awg.get("subscribers_enabled") is False)
    production=(manifest.get("state")=="active" and
            manifest.get("activation_enabled") is True and
            manifest.get("registration_enabled") is True and
            awg.get("state")=="active" and
            awg.get("activation_enabled") is True and
            awg.get("peers_enabled") is True and
            awg.get("subscribers_enabled") is False)
    return "STAGED" if staged else "PRODUCTION" if production else "UNKNOWN"

def material()->dict:
    require_identity()
    if state()!="STAGED" or any(active_unit(unit) for unit in UNITS):
        raise Blocked("node not staged")
    if Path("/sys/class/net/awg0").exists():raise Blocked("AWG interface present")
    report=validate_awg(DATA)
    if report.get("mode")!="staged" or report.get("zero_peers") is not True:
        raise Blocked("staged AWG not verified")
    config=safe_manifest(AWG/"manifest.json")
    return {
        "nodeId":NODE,"endpointHost":trust.HOST,
        "configSha256":config["config_sha256"],
        "serverPublicKeySha256":hashlib.sha256(canonical_key(config["server_public_key"])).hexdigest(),
        "sourceBinarySha256":config["source_binary_sha256"],
    }

def incoming(path:Path)->dict:
    raw=protected(path,4096)
    approval=json.loads(raw)
    if not isinstance(approval,dict):raise Blocked("invalid approval")
    spki=trust.pinned_spki(DATA/"controller-access.spki",trust.CONTROLLER_SHA)
    verify_approval(approval,spki)
    expected=material()
    for input_key,field in (
        ("nodeId","nodeId"),("endpointHost","endpointHost"),
        ("configSha256","configSha256"),
        ("serverPublicKeySha256","serverPublicKeySha256"),
        ("sourceBinarySha256","sourceBinarySha256")):
        if approval[input_key]!=expected[field]:
            raise Blocked("signed AWG identity not current")
    return approval

def save(path:Path,data:bytes,*,replace:bool)->None:
    if path.is_symlink():raise Blocked("symlink target")
    fd,tmp=tempfile.mkstemp(prefix=".fi217-production-",dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        if replace:os.replace(tmp,path)
        else:os.link(tmp,path,follow_symlinks=False)
        dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:Path(tmp).unlink(missing_ok=True)

def backed_up()->None:
    if BACK.is_symlink():raise Blocked("backup symlink")
    if not BACK.exists():BACK.mkdir(mode=0o700)
    info=BACK.stat()
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
        raise Blocked("untrusted backup")
    for name in FILES:
        before=protected(DATA/name)
        target=BACK/name.replace("/","__")
        if not target.exists():save(target,before,replace=False)
        if protected(target)!=before:raise Blocked("unexpected existing backup")

def restore()->None:
    for name in FILES:
        backup=BACK/name.replace("/","__")
        source=protected(backup)
        if not source:raise Blocked("backup missing")
        save(DATA/name,source,replace=True)
    if APPROVAL.exists():
        if APPROVAL.is_symlink():raise Blocked("approval symlink")
        APPROVAL.unlink()
    if state()!="STAGED":raise Blocked("restore failed")

def rollback()->None:
    for unit in reversed(UNITS):
        run(["systemctl","stop",unit],timeout=40,check=False)
        run(["systemctl","disable",unit],timeout=20,check=False)
    try:
        awg_egress.down()
    except (OSError,ValueError,subprocess.SubprocessError):
        # Do not restore staged manifest if new NAT rules could remain.
        raise Blocked("network rollback not verified")
    if Path("/sys/class/net/awg0").exists():
        raise Blocked("AWG interface survived stop")
    restore()

def install_units(source:Path)->None:
    if source.is_symlink() or not source.is_dir() or source.stat().st_uid!=0:
        raise Blocked("untrusted staging directory")
    if any(active_unit(unit) for unit in UNITS):
        raise Blocked("unit already running")
    node_ready(ROOT,NODE)
    awg_egress.install_code(source/"awg_egress.py")
    install_awg_watchdog.install(DATA,source/"awg_peer_grants.py")
    # Existing AWG unit has already been installed with exact pinned source.
    src=Path("/etc/systemd/system/mnebyvpn-nodekit-awg@.service")
    if src.is_symlink() or not src.is_file():
        raise Blocked("AWG unit missing")
    from awg_lifecycle import unit_source
    if src.read_text()!=unit_source():
        raise Blocked("AWG unit changed")
    for unit in UNITS:
        result=run(["systemctl","is-enabled",unit],check=False)
        if result.returncode==0:
            raise Blocked("unexpected preenabled AWG service")

def configure(approval:dict)->None:
    backed_up()
    node=safe_manifest(DATA/"manifest.json")
    awg=safe_manifest(AWG/"manifest.json")
    if state()!="STAGED" or APPROVAL.exists() or APPROVAL.is_symlink():
        raise Blocked("node no longer staged")
    node.update(state="active",activation_enabled=True,registration_enabled=True)
    awg.update(state="active",activation_enabled=True,peers_enabled=True,
               subscribers_enabled=False)
    # Validate exact controller approval in memory before any filesystem mutations.
    from unittest.mock import patch
    with patch("fi_awg_production_policy.safe_manifest",return_value=approval):
        admit(DATA,node,awg)
    save(APPROVAL,(json.dumps(approval,sort_keys=True,separators=(",",":"))+"\n").encode(),replace=False)
    save(DATA/"manifest.json",(json.dumps(node,sort_keys=True)+"\n").encode(),replace=True)
    save(AWG/"manifest.json",(json.dumps(awg,sort_keys=True)+"\n").encode(),replace=True)
    report=validate_awg(DATA)
    if report.get("mode")!="production" or report.get("production_approval")!="signed":
        raise Blocked("signed production validation failed")

def verify_live()->None:
    if state()!="PRODUCTION":raise Blocked("not in production")
    result=validate_awg(DATA)
    if result.get("mode")!="production":raise Blocked("not signed production")
    for unit in UNITS:
        if not active_unit(unit):raise Blocked("unit inactive")
        en=run(["systemctl","is-enabled",unit],check=False)
        if en.returncode:raise Blocked("unit not persistent")
    if not Path("/sys/class/net/awg0").is_dir():
        raise Blocked("AWG interface missing")
    p=run([str(AWG_BIN/"awg"),"show","awg0","listen-port"],timeout=12).stdout.strip()
    if p!="51821":raise Blocked("AWG listen port drift")
    peers=run([str(AWG_BIN/"awg"),"show","awg0","peers"],timeout=12).stdout.strip()
    if peers:raise Blocked("unexpected customer peers before release")
    ip=run(["ip","-o","-4","addr","show","dev","awg0"]).stdout
    if "10.73.91.1/24" not in ip:raise Blocked("AWG address drift")
    report=awg_egress.up()
    if report.get("network_enabled") is not True:
        raise Blocked("NAT not verified")

def activate(approval_path:Path,source:Path)->None:
    require_identity()
    approval=incoming(approval_path)
    install_units(source)
    try:
        configure(approval)
        for unit in UNITS:
            run(["systemctl","enable",unit],timeout=15)
            run(["systemctl","start",unit],timeout=65)
        verify_live()
    except BaseException:
        rollback()
        raise

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("export","activate","verify"),required=True)
    p.add_argument("--approval",type=Path)
    p.add_argument("--source",type=Path)
    args=p.parse_args()
    try:
        require_identity()
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            meta=os.fstat(fd)
            if meta.st_uid!=0 or not stat.S_ISREG(meta.st_mode) or meta.st_mode&0o077:
                raise Blocked("untrusted lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.mode=="export":
                print(json.dumps(material(),sort_keys=True,separators=(",",":")))
            elif args.mode=="activate":
                if not args.approval or not args.source:raise Blocked("approval or source missing")
                activate(args.approval,args.source)
                print("FI_AWG_PRODUCTION=ACTIVE;SIGNED=true;WATCHDOG=ACTIVE;EGRESS=ACTIVE;CUSTOMER_RELEASE_UNCHANGED=true")
            else:
                verify_live()
                print("FI_AWG_PRODUCTION=VERIFIED;WATCHDOG=ACTIVE;EGRESS=ACTIVE;CUSTOMER_RELEASE_UNCHANGED=true")
            return 0
        finally:os.close(fd)
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError,
            trust.CanaryError):
        print("FI_AWG_PRODUCTION=BLOCKED;CHECK_SYSTEMD_LOGS=true",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
