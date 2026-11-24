#!/usr/bin/env python3
"""Stage controller-initiated private FI DNS SSH, with guarded rollback."""
from __future__ import annotations
import asyncio
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from fi_dns_ssh_stage import (RU,FI,RU_ROOT,RU_RUNTIME,FI_ROOT,FI_RUNTIME,
    CONTROLLER_PIN,NODE_PIN,require,private_dir,read,immutable,command,host,verify_pin)

COMMENT="mnebyvpn-fi-dns-reverse-v1"
COMMAND="fi-dns-reverse-v1"
KEY=RU_ROOT/"fi-dns-reverse-ssh"
UNIT="mnebyvpn-fi-dns-reverse.service"
UNIT_PATH=Path("/etc/systemd/system")/UNIT
FI_STATE=FI_ROOT/"dns-reverse"
AUTH=Path("/root/.ssh/authorized_keys")


def parse_key(raw):
    fields=raw.decode("ascii").strip().split()
    require(len(fields)==3 and fields[0]=="ssh-ed25519" and fields[2]==COMMENT,"invalid_reverse_key")
    wire=base64.b64decode(fields[1],validate=True)
    require(len(wire)==51 and wire[:19]==b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" and base64.b64encode(wire).decode()==fields[1],"invalid_reverse_key_wire")
    return fields[1]


def prepare_ru(src):
    host(RU);private_dir(RU_ROOT);private_dir(RU_RUNTIME)
    verify_pin(RU_ROOT/"fi-node-public.spki",NODE_PIN)
    verify_pin(RU_ROOT/"controller-public.spki",CONTROLLER_PIN)
    for name in ("meter","publisher"):
        command("systemctl","is-active","--quiet","mnebyvpn-fi-dns-"+name+".service")
    # Validate the actual network direction before creating credentials.
    try:
        with socket.create_connection((FI,22),timeout=5) as sock:
            sock.settimeout(4)
            require(sock.recv(256).startswith(b"SSH-"),"reverse_ssh_banner_missing")
    except OSError:
        raise RuntimeError("ru_to_fi_ssh_unreachable")
    print("RU_TO_FI_SSH_TCP_VERIFIED=true",flush=True)
    hosts=read(RU_ROOT/"fi-known_hosts",512)
    fields=hosts.decode("ascii").strip().split()
    require(len(fields)==3 and fields[:2]==["fi.mnebyvpn.site","ssh-ed25519"],"missing_fi_host_pin")
    require(len(base64.b64decode(fields[2],validate=True))==51,"invalid_fi_host_pin")
    pub=KEY.with_suffix(".pub")
    require(KEY.exists()==pub.exists() and not KEY.is_symlink() and not pub.is_symlink(),"partial_reverse_identity")
    if not KEY.exists():
        command("/usr/bin/ssh-keygen","-q","-t","ed25519","-N","","-C",COMMENT,"-f",str(KEY))
        KEY.chmod(0o600);pub.chmod(0o600)
    read(KEY,8192)
    data=read(pub,1000)
    key=parse_key(data)
    require(command("/usr/bin/ssh-keygen","-y","-f",str(KEY)).decode().split()[:2]==["ssh-ed25519",key],"reverse_keypair_mismatch")
    immutable(src/"ru-public.key",data)
    for name in ("fi_dns_reverse_channel.py","fi_dns_ssh_bridge.py"):
        immutable(RU_RUNTIME/name,read(src/name,100000))


def change_auth(src,remove=False):
    host(FI);private_dir(AUTH.parent)
    key=parse_key(read(src/"ru-public.key",1000))
    entry=('restrict,from="'+RU+'",command="/usr/bin/python3 '+str(FI_RUNTIME/"fi_dns_reverse_channel.py")+'" ssh-ed25519 '+key+' '+COMMENT).encode()
    marker=src/"new-auth"
    if remove and not marker.exists():return
    if remove:require(read(marker,2000)==entry+b"\n","rollback_key_mismatch")
    fd=os.open(AUTH.parent/".fi-dns-reverse.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o077,"unsafe_lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old=read(AUTH,256000) if AUTH.exists() or AUTH.is_symlink() else b""
        matches=[x for x in old.splitlines() if key.encode() in x or COMMENT.encode() in x]
        if matches:require(matches==[entry],"conflicting_reverse_auth")
        if remove:
            if not matches:return
            new=b"".join(x for x in old.splitlines(keepends=True) if x.rstrip(b"\r\n")!=entry)
        elif matches:return
        else:
            immutable(marker,entry+b"\n")
            new=old+(b"\n" if old and not old.endswith(b"\n") else b"")+entry+b"\n"
        out,tmp=tempfile.mkstemp(prefix=".fi-dns-reverse-",dir=AUTH.parent)
        try:
            with os.fdopen(out,"wb") as f:f.write(new);f.flush();os.fsync(f.fileno())
            require((read(AUTH,256000) if AUTH.exists() or AUTH.is_symlink() else b"")==old,"authorized_keys_changed")
            os.replace(tmp,AUTH)
            dfd=os.open(AUTH.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        finally:Path(tmp).unlink(missing_ok=True)
    finally:os.close(fd)
    print("FI_DNS_REVERSE_AUTH_"+("ROLLED_BACK" if remove else "STAGED")+"=true")


def prepare_fi(src):
    host(FI);private_dir(FI_ROOT);private_dir(FI_RUNTIME)
    verify_pin(FI_ROOT/"identity/node-public.spki",NODE_PIN)
    verify_pin(FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
    private_dir(FI_STATE,True)
    for name in ("fi_dns_reverse_channel.py","fi_dns_ssh_bridge.py"):
        immutable(FI_RUNTIME/name,read(src/name,100000))
    change_auth(src)


def repair_fi_clock(src):
    host(FI);private_dir(FI_RUNTIME)
    script=FI_RUNTIME/"fi_dns_reverse_clock.py"
    immutable(script,read(src/script.name,100000))
    # Native NTP is preferred. Restart only the existing time service,
    # never network/VPN services. Independently verify HTTPS time afterward.
    sync=command("timedatectl","show","-p","NTPSynchronized","--value").strip()
    if sync!=b"yes":
        command("systemctl","is-active","--quiet","systemd-timesyncd.service")
        command("systemctl","restart","systemd-timesyncd.service")
        for _ in range(10):
            if command("timedatectl","show","-p","NTPSynchronized","--value").strip()==b"yes":break
            time.sleep(2)
    result=subprocess.run(["/usr/bin/python3",str(script),"--repair"],timeout=35)
    require(result.returncode==0,"fi_clock_repair_failed")
    # Keep native NTP active. A bounded independent HTTPS fallback checks
    # every two minutes only while NTP is unsynchronized.
    unitdir=Path("/etc/systemd/system")
    names=("mnebyvpn-fi-clock.service","mnebyvpn-fi-clock.timer")
    for name in names:
        for base in (unitdir,Path("/run/systemd/system"),Path("/usr/lib/systemd/system"),Path("/lib/systemd/system")):
            require(not (base/(name+".d")).exists() and not (base/(name+".d")).is_symlink(),"foreign_clock_override")
            if base!=unitdir:require(not (base/name).exists() and not (base/name).is_symlink(),"foreign_clock_unit")
        immutable(unitdir/name,read(src/name,10000))
    command("systemd-analyze","verify",*(str(unitdir/name) for name in names))
    command("systemctl","daemon-reload")
    command("systemctl","enable","--now","mnebyvpn-fi-clock.timer")
    command("systemctl","is-active","--quiet","mnebyvpn-fi-clock.timer")
    print("FI_CLOCK_FALLBACK_TIMER_ACTIVE=true",flush=True)


def start_ru(src):
    host(RU)
    for base in (Path("/etc/systemd/system"),Path("/run/systemd/system"),Path("/usr/lib/systemd/system"),Path("/lib/systemd/system")):
        drop=base/(UNIT+".d")
        require(not drop.exists() and not drop.is_symlink(),"reverse_override_present")
        if base!=UNIT_PATH.parent:
            path=base/UNIT
            require(not path.exists() and not path.is_symlink(),"foreign_reverse_unit")
    active=subprocess.run(["systemctl","is-active","--quiet",UNIT],capture_output=True,timeout=5).returncode==0
    require(not active,"reverse_already_active")
    immutable(UNIT_PATH,read(src/UNIT,10000))
    command("systemd-analyze","verify",str(UNIT_PATH))
    command("systemctl","daemon-reload")
    immutable(src/"started",b"private-reverse-stage-v1\n")
    command("systemctl","start",UNIT)
    print("RU_DNS_REVERSE_SERVICE_STARTED=true")


async def probe_fi():
    host(FI);sys.path.insert(0,str(FI_RUNTIME))
    from fi_dns_reverse_channel import ReverseTransport,SOCKET,PING_OP,PONG
    from fi_dns_meter_rpc import protected_openssl_meter,unique_object
    from fi_dns_signed_grants import validate,verify_signature,utc_seconds,ENVELOPE_KEYS,NODE,COUNTRY,SIGNATURE
    transport=ReverseTransport()
    for _ in range(20):
        try:
            if await transport.exchange(PING_OP,timeout=2)==PONG:break
        except (OSError,ValueError,TimeoutError,asyncio.IncompleteReadError):pass
        await asyncio.sleep(.5)
    else:raise RuntimeError("reverse_ping_failed")
    print("FI_DNS_REVERSE_PING=PASS",flush=True)
    phase="snapshot_transport"
    try:
        raw=await transport.snapshot()
        print("FI_DNS_REVERSE_SNAPSHOT_FRAME=PASS",flush=True)
        phase="snapshot_schema"
        candidate=json.loads(raw,object_pairs_hook=unique_object)
        # Report only structural booleans, and signed timing deltas. Never
        # disclose the snapshot, grant list, signature or credential digest.
        now=time.time()
        shape=isinstance(candidate,dict) and set(candidate)==ENVELOPE_KEYS
        require(shape,"snapshot_envelope_shape")
        checks={
            "schema_version":type(candidate["schemaVersion"]) is int and candidate["schemaVersion"]==1,
            "node":candidate["nodeId"]==NODE,
            "country":candidate["countryCode"]==COUNTRY,
            "revision":type(candidate["revision"]) is int and 1<=candidate["revision"]<=1000000000,
            "empty_grants":candidate["grants"]==[],
            "signature_shape":isinstance(candidate["signature"],str) and SIGNATURE.fullmatch(candidate["signature"]) is not None,
        }
        print("FI_DNS_SNAPSHOT_SHAPE="+json.dumps(checks,sort_keys=True),flush=True)
        require(all(checks.values()),"snapshot_shape_mismatch")
        issued=utc_seconds(candidate["issuedAt"])
        until=utc_seconds(candidate["validUntil"])
        # Verify the signed transcript before trusting time fields. This does
        # not authorize any grant or relax the real receiver's time check.
        verify_signature(candidate,FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
        print("FI_DNS_SNAPSHOT_TIMING="+json.dumps({
            "age_ms":round((now-issued)*1000),
            "remaining_ms":round((until-now)*1000),
            "signed_ttl_ms":round((until-issued)*1000),
        },sort_keys=True),flush=True)
        snapshot=validate(candidate,now)
        print("FI_DNS_REVERSE_SNAPSHOT_SCHEMA=PASS",flush=True)
        phase="snapshot_signature"
        verify_signature(snapshot,FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
        require(snapshot["grants"]==[],"unexpected_live_grants")
        print("FI_DNS_REVERSE_SNAPSHOT_SIGNATURE=PASS",flush=True)
        phase="meter_key"
        meter=protected_openssl_meter(transport,FI_ROOT/"identity/node-private.pk8",FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
        # Separate local signing from transport and decision verification.
        require(len(meter.node_sign(b"FI_DNS_PRIVATE_LOCAL_KEY_CHECK"))==64,"node_local_sign_failed")
        print("FI_DNS_REVERSE_NODE_SIGN=PASS",flush=True)
    except (OSError,ValueError,TypeError,RuntimeError,subprocess.SubprocessError,asyncio.IncompleteReadError) as exc:
        print("FI_DNS_REVERSE_PROBE_FAILURE="+phase+":"+type(exc).__name__,flush=True)
        raise RuntimeError(phase+"_failed") from None
    started=time.monotonic()
    values=[]
    for _ in range(5):
        t=time.monotonic()
        try:
            decision=await meter._apply("reserve",uuid.uuid4(),secrets.token_hex(32))
            require(decision=="DENY_DISABLED","wrong_meter_gate")
        except (OSError,ValueError,TypeError,RuntimeError,subprocess.SubprocessError,asyncio.IncompleteReadError) as exc:
            print("FI_DNS_REVERSE_METER_FAILURE="+type(exc).__name__,flush=True)
            raise RuntimeError("signed_meter_probe_failed") from None
        values.append(round((time.monotonic()-t)*1000))
    print("FI_DNS_REVERSE_SIGNED_RPC_MS="+json.dumps(values),flush=True)
    print("FI_DNS_REVERSE_CHANNEL_VERIFIED=true;SIGNED_EMPTY_SNAPSHOT=true;SIGNED_METER_DENIAL=true;PUBLIC_DNS_UNCHANGED=true")


if __name__=="__main__":
    try:
        os.umask(0o077)
        if sys.argv[1:]==["probe"]:asyncio.run(probe_fi())
        else:
            require(len(sys.argv)==3 and re.fullmatch(r"/run/fi-dns-reverse-[0-9]+-[0-9]+",sys.argv[2]),"invalid_reverse_stage")
            src=Path(sys.argv[2]);private_dir(src)
            action=sys.argv[1]
            if action=="ru":prepare_ru(src)
            elif action=="fi":prepare_fi(src)
            elif action=="clock":repair_fi_clock(src)
            elif action=="start":start_ru(src)
            elif action=="rollback-fi":change_auth(src,True)
            elif action=="rollback-ru":
                host(RU)
                if (src/"started").exists():
                    command("systemctl","stop",UNIT)
                    print("RU_DNS_REVERSE_SERVICE_STOPPED=true")
            else:raise RuntimeError("invalid_reverse_action")
    except (OSError,ValueError,RuntimeError,TypeError,subprocess.SubprocessError,asyncio.IncompleteReadError) as exc:
        label=str(exc) if isinstance(exc,RuntimeError) and re.fullmatch("[a-z0-9_]+",str(exc)) else "reverse_stage_failed"
        print("FI_DNS_REVERSE_BLOCKED="+label,file=sys.stderr)
        raise SystemExit(2)
