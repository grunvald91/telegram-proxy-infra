#!/usr/bin/env python3
"""Stage and prove a dedicated FI-to-RU private forced-command channel.

Existing pinned SSH is used only to install root-owned reviewed files and
public keys. No SSH daemon configuration, network listener, VPN or public
DNS change. The FI private SSH key never leaves FI.
"""
from __future__ import annotations
import asyncio
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
import tempfile
import uuid

RU="188.120.254.223"
FI="217.11.167.91"
RU_ROOT=Path("/root/mnebyvpn-controller")
RU_RUNTIME=Path("/opt/mnebyvpn-fi-dns-controller")
RU_STATE=Path("/var/lib/mnebyvpn-fi-dns-controller")
FI_ROOT=Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
FI_RUNTIME=Path("/opt/mnebyvpn-fi-dns-node")
FI_CHANNEL=FI_ROOT/"dns-channel"
CONTROLLER_PIN="e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_PIN="c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
COMMENT="mnebyvpn-fi-dns-rpc-v1"
MODULES=("fi_dns_ssh_bridge.py","fi_dns_ssh_client.py","fi_dns_meter_rpc.py",
         "fi_enrollment_ssh.py","fi_dns_signed_grants.py")


def require(ok,label):
    if not ok:raise RuntimeError(label)


def private_dir(path,create=False):
    if create:path.mkdir(mode=0o700,exist_ok=True)
    s=path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_mode&0o077==0,"unsafe_dir")


def read(path,limit=700000):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as file:
        s=os.fstat(file.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_mode&0o077==0 and s.st_nlink==1 and 0<s.st_size<=limit,"unsafe_file")
        data=file.read(limit+1)
        require(len(data)==s.st_size,"file_changed")
        return data


def immutable(path,data):
    if path.exists() or path.is_symlink():
        require(read(path,max(len(data),1))==data,"existing_asset_drift")
        return
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as file:
        file.write(data);file.flush();os.fsync(file.fileno())


def command(*args,timeout=12,input=None):
    result=subprocess.run(args,input=input,capture_output=True,timeout=timeout)
    require(result.returncode==0,"private_channel_command_failed")
    return result.stdout


def host(address):
    require(os.geteuid()==0,"root_required")
    for _,name in socket.if_nameindex():
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                value=fcntl.ioctl(sock.fileno(),0x8915,struct.pack("256s",name.encode()))
                if socket.inet_ntoa(value[20:24])==address:return
        except OSError:pass
    raise RuntimeError("unexpected_host")


def verify_pin(path,pin):
    der=read(path,100)
    require(len(der)==44 and hashlib.sha256(der).hexdigest()==pin,"identity_pin_mismatch")


def parse_pub(raw):
    fields=raw.decode("ascii").strip().split()
    require(len(fields)==3 and fields[0]=="ssh-ed25519" and fields[2]==COMMENT,"invalid_dedicated_public_key")
    data=base64.b64decode(fields[1],validate=True)
    require(len(data)==51 and data[:19]==b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20","invalid_ssh_key_wire")
    require(base64.b64encode(data).decode()==fields[1],"noncanonical_ssh_key")
    return fields[1]


def pinned_hosts(raw):
    lines=[x for x in raw.decode("ascii").splitlines() if x.startswith(RU+" ")]
    require(len(lines)==1,"missing_independent_ru_host_pin")
    fields=lines[0].split()
    require(len(fields)==3 and fields[1]=="ssh-ed25519","invalid_ru_host_pin")
    data=base64.b64decode(fields[2],validate=True)
    require(len(data)==51 and data[:19]==b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20","invalid_ru_host_pin_wire")
    return (lines[0]+"\n").encode()


def prepare_fi(src):
    host(FI)
    private_dir(FI_ROOT);private_dir(FI_ROOT/"identity")
    verify_pin(FI_ROOT/"identity/node-public.spki",NODE_PIN)
    verify_pin(FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
    read(FI_ROOT/"identity/node-private.pk8",256)
    require(command("/usr/bin/openssl","pkey","-inform","DER","-in",str(FI_ROOT/"identity/node-private.pk8"),"-pubout","-outform","DER")==read(FI_ROOT/"identity/node-public.spki",100),"node_private_pin_mismatch")
    manifest=json.loads(read(FI_ROOT/"manifest.json",10000))
    require(manifest.get("node_id")=="fi-test-01" and manifest.get("state")=="active","unexpected_fi_manifest")
    private_dir(FI_RUNTIME,True);private_dir(FI_CHANNEL,True)
    for name in MODULES:immutable(FI_RUNTIME/name,read(src/name,100000))
    immutable(FI_CHANNEL/"known_hosts",pinned_hosts(read(src/"ru-known_hosts",10000)))
    key=FI_CHANNEL/"identity"
    pub=FI_CHANNEL/"identity.pub"
    require(key.exists()==pub.exists() and not key.is_symlink() and not pub.is_symlink(),"partial_channel_identity")
    if not key.exists():
        command("/usr/bin/ssh-keygen","-q","-t","ed25519","-N","","-C",COMMENT,"-f",str(key))
        key.chmod(0o600);pub.chmod(0o600)
    read(key,8192)
    value=read(pub,1000)
    encoded=parse_pub(value)
    require(command("/usr/bin/ssh-keygen","-y","-f",str(key)).decode().split()[:2]==["ssh-ed25519",encoded],"channel_keypair_mismatch")
    immutable(src/"fi-public.key",value)
    print("FI_DNS_DEDICATED_SSH_KEY_READY=true")


def stage_ru(src):
    host(RU)
    private_dir(RU_ROOT);private_dir(RU_RUNTIME);private_dir(RU_STATE)
    verify_pin(RU_ROOT/"fi-node-public.spki",NODE_PIN)
    verify_pin(RU_ROOT/"controller-public.spki",CONTROLLER_PIN)
    for mode in ("meter","publisher"):
        command("systemctl","is-active","--quiet","mnebyvpn-fi-dns-"+mode+".service")
    key=parse_pub(read(src/"fi-public.key",1000))
    immutable(RU_RUNTIME/"fi_dns_ssh_bridge.py",read(src/"fi_dns_ssh_bridge.py",100000))
    private_dir(RU_STATE/"ssh-slots",True)
    directory=Path("/root/.ssh")
    private_dir(directory)
    path=directory/"authorized_keys"
    lock=os.open(directory/".fi-dns-channel.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(lock)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o077,"unsafe_lock")
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        current=read(path,256000) if path.exists() or path.is_symlink() else b""
        entry=('restrict,from="'+FI+'",command="/usr/bin/python3 '+str(RU_RUNTIME/"fi_dns_ssh_bridge.py")+'" ssh-ed25519 '+key+' '+COMMENT).encode()
        matching=[line for line in current.splitlines() if key.encode() in line or COMMENT.encode() in line]
        if matching:
            require(matching==[entry],"conflicting_authorized_key")
        else:
            immutable(src/"new-authorized-key",entry+b"\n")
            data=current+(b"\n" if current and not current.endswith(b"\n") else b"")+entry+b"\n"
            fd,tmp=tempfile.mkstemp(prefix=".fi-dns-auth-",dir=directory)
            try:
                with os.fdopen(fd,"wb") as f:
                    f.write(data);f.flush();os.fsync(f.fileno())
                require((read(path,256000) if path.exists() or path.is_symlink() else b"")==current,"authorized_keys_changed")
                os.replace(tmp,path)
                dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(dfd)
                finally:os.close(dfd)
            finally:Path(tmp).unlink(missing_ok=True)
    finally:os.close(lock)
    print("RU_FI_DNS_FORCED_COMMAND_READY=true")

def rollback_ru(src):
    host(RU)
    marker=src/"new-authorized-key"
    if not marker.exists():
        return
    entry=read(marker,2000).rstrip(b"\n")
    key=parse_pub(read(src/"fi-public.key",1000))
    expected=('restrict,from="'+FI+'",command="/usr/bin/python3 '+str(RU_RUNTIME/"fi_dns_ssh_bridge.py")+'" ssh-ed25519 '+key+' '+COMMENT).encode()
    require(entry==expected,"rollback_entry_mismatch")
    directory=Path("/root/.ssh")
    private_dir(directory)
    path=directory/"authorized_keys"
    lock=os.open(directory/".fi-dns-channel.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(lock)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o077,"unsafe_lock")
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        current=read(path,256000)
        matches=[line for line in current.splitlines() if line==entry]
        if not matches:
            return
        require(len(matches)==1,"duplicate_rollback_entry")
        rows=current.splitlines(keepends=True)
        data=b"".join(line for line in rows if line.rstrip(b"\r\n")!=entry)
        fd,tmp=tempfile.mkstemp(prefix=".fi-dns-rollback-",dir=directory)
        try:
            with os.fdopen(fd,"wb") as f:
                f.write(data);f.flush();os.fsync(f.fileno())
            require(read(path,256000)==current,"authorized_keys_changed")
            os.replace(tmp,path)
            dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        finally:Path(tmp).unlink(missing_ok=True)
    finally:os.close(lock)
    print("FI_DNS_NEW_SSH_AUTH_ROLLED_BACK=true")


async def probe():
    host(FI)
    sys.path.insert(0,str(FI_RUNTIME))
    from fi_dns_ssh_client import MeterPool,ssh_args
    from fi_dns_meter_rpc import protected_openssl_meter,unique_object
    from fi_dns_signed_grants import validate,verify_signature
    import time
    args=ssh_args(FI_CHANNEL/"identity",FI_CHANNEL/"known_hosts")
    bad=await asyncio.create_subprocess_exec(*args[:-1],"false",stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
    try:
        output,_=await asyncio.wait_for(bad.communicate(),8)
        require(bad.returncode!=0 and output==b"","forced_command_not_restricted")
    finally:
        if bad.returncode is None:
            bad.kill();await bad.wait()
    # Diagnose one session before starting the pool. Never emit raw SSH
    # debug output (paths, keys and system configuration are sensitive).
    import struct
    from fi_dns_ssh_bridge import PING_OP,PONG
    verbose=[*args[:1],"-v",*args[1:]]
    ping=await asyncio.create_subprocess_exec(*verbose,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    try:
        output,debug=await asyncio.wait_for(ping.communicate(struct.pack("!I",len(PING_OP))+PING_OP),10)
        checks={
            "tcp_connected":b"Connection established" in debug,
            "host_verified":b"is known and matches" in debug,
            "key_offered":b"Offering public key" in debug,
            "key_accepted":b"Server accepts key" in debug,
            "authenticated":b"Authenticated to " in debug,
            "command_sent":b"Sending command:" in debug,
            "permission_denied":b"Permission denied" in debug,
            "connection_timeout":b"Connection timed out" in debug,
            "connection_refused":b"Connection refused" in debug,
            "remote_closed":b"Connection closed" in debug or b"Connection reset" in debug,
        }
        print("FI_DNS_SSH_DIAGNOSTIC="+json.dumps(checks,sort_keys=True),flush=True)
        require(ping.returncode==0 and output==struct.pack("!I",len(PONG))+PONG,"single_ssh_ping_failed")
    finally:
        if ping.returncode is None:
            ping.kill();await ping.wait()
    pool=MeterPool(args)
    try:
        await pool.warm()
        raw=await pool.snapshot()
        snapshot=validate(json.loads(raw,object_pairs_hook=unique_object),time.time())
        verify_signature(snapshot,FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
        require(snapshot["grants"]==[],"unexpected_live_grants")
        meter=protected_openssl_meter(pool,FI_ROOT/"identity/node-private.pk8",FI_ROOT/"controller-access.spki",CONTROLLER_PIN)
        result=await meter._apply("reserve",uuid.uuid4(),secrets.token_hex(32))
        require(result=="DENY_DISABLED","unexpected_meter_gate")
        print("FI_DNS_PRIVATE_CHANNEL_VERIFIED=true;SIGNED_EMPTY_SNAPSHOT=true;SIGNED_METER_DENIAL=true;PUBLIC_DNS_UNCHANGED=true")
    finally:await pool.close()


if __name__=="__main__":
    try:
        os.umask(0o077)
        if sys.argv[1:]==["probe"]:
            asyncio.run(probe())
        else:
            require(len(sys.argv)==3 and re.fullmatch(r"/run/fi-dns-bridge-[0-9]+-[0-9]+",sys.argv[2]),"invalid_stage")
            src=Path(sys.argv[2]);private_dir(src)
            if sys.argv[1]=="fi":prepare_fi(src)
            elif sys.argv[1]=="ru":stage_ru(src)
            elif sys.argv[1]=="rollback":rollback_ru(src)
            else:raise RuntimeError("invalid_action")
    except (OSError,ValueError,TypeError,RuntimeError,subprocess.SubprocessError,asyncio.TimeoutError,asyncio.IncompleteReadError) as exc:
        label=str(exc) if isinstance(exc,RuntimeError) and re.fullmatch("[a-z0-9_]+",str(exc)) else "channel_stage_failed"
        print("FI_DNS_CHANNEL_BLOCKED="+label,file=sys.stderr)
        raise SystemExit(2)
