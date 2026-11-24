#!/usr/bin/env python3
"""Controller-initiated private DNS channel over fixed SSH stdio.

RU initiates TCP; FI's forced command exposes only a root-only UNIX socket.
No SSH forwarding, public listener or shell. Signed RPC still authenticates
each request and result independently.
"""
from __future__ import annotations
import asyncio
import fcntl
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import time

from fi_dns_ssh_bridge import (MAX_REQUEST,MAX_SNAPSHOT,PING_OP,PONG,SNAPSHOT_OP,
    read_exact,write_frame,recv_exact,serve)

COMMAND="fi-dns-reverse-v1"
SOCKET=Path("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-reverse/channel.sock")
KEY=Path("/root/mnebyvpn-controller/fi-dns-reverse-ssh")
HOSTS=Path("/root/mnebyvpn-controller/fi-known_hosts")


def ssh_args():
    return ["/usr/bin/ssh","-F","/dev/null","-T","-o","BatchMode=yes",
            "-o","IdentitiesOnly=yes","-o","PasswordAuthentication=no",
            "-o","KbdInteractiveAuthentication=no","-o","StrictHostKeyChecking=yes",
            "-o","HostKeyAlgorithms=ssh-ed25519","-o","HostKeyAlias=fi.mnebyvpn.site",
            "-o","UserKnownHostsFile="+str(HOSTS),"-o","GlobalKnownHostsFile=/dev/null",
            "-o","UpdateHostKeys=no","-o","ForwardAgent=no","-o","ClearAllForwardings=yes",
            "-o","ControlMaster=no","-o","ProxyCommand=none","-o","ConnectTimeout=6",
            "-o","ServerAliveInterval=15","-o","ServerAliveCountMax=2","-o","LogLevel=ERROR",
            "-i",str(KEY),"root@217.11.167.91",COMMAND]


def limit_for(data):
    return MAX_SNAPSHOT if data==SNAPSHOT_OP else MAX_REQUEST


def handle_local(conn,infd,outfd):
    # Linux SO_PEERCRED: root only even if directory ACL is later changed.
    _,uid,_=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if uid!=0: return
    conn.settimeout(2)
    try:
        n=struct.unpack("!I",recv_exact(conn,4))[0]
        if not 1<=n<=MAX_REQUEST:return
        data=recv_exact(conn,n)
    except (OSError,EOFError,ValueError):
        return
    # A lost/invalid remote reply terminates this whole session. Never let a
    # late reply be interpreted as the answer to the next local request.
    write_frame(outfd,data)
    timeout=8 if data==SNAPSHOT_OP else 3
    size=struct.unpack("!I",read_exact(infd,4,timeout))[0]
    if not 1<=size<=limit_for(data):raise ValueError("unsafe reply")
    reply=read_exact(infd,size,timeout)
    try:
        conn.sendall(struct.pack("!I",size)+reply)
    except OSError:
        # Client disappeared; the complete remote reply was consumed.
        pass


def fi_serve(path=SOCKET,infd=0,outfd=1):
    parent=path.parent
    s=parent.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077:
        raise ValueError("unsafe socket directory")
    lock=os.open(parent/"channel.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    owned=False
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if path.exists() or path.is_symlink():
            old=path.lstat()
            if not stat.S_ISSOCK(old.st_mode) or old.st_uid!=0:raise ValueError("unsafe stale socket")
            path.unlink()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(path));owned=True;path.chmod(0o600);server.listen(8)
            server.settimeout(20)
            # Periodic ping also prevents RU bridge idle timeout.
            end=time.monotonic()+3500
            while time.monotonic()<end:
                try:conn,_=server.accept()
                except socket.timeout:
                    write_frame(outfd,PING_OP)
                    size=struct.unpack("!I",read_exact(infd,4,3))[0]
                    if size!=len(PONG) or read_exact(infd,size,3)!=PONG:raise ValueError("ping failed")
                    continue
                with conn:handle_local(conn,infd,outfd)
    finally:
        if owned:path.unlink(missing_ok=True)
        os.close(lock)


class ReverseTransport:
    def __init__(self,path=SOCKET):
        self.path=path
        self.lock=asyncio.Lock()

    async def exchange(self,data,timeout=2.7):
        if not isinstance(data,bytes) or not 1<=len(data)<=MAX_REQUEST:raise ValueError("invalid request")
        async with asyncio.timeout(timeout):
            async with self.lock:
                reader,writer=await asyncio.open_unix_connection(str(self.path))
                try:
                    writer.write(struct.pack("!I",len(data))+data)
                    await writer.drain()
                    n=struct.unpack("!I",await reader.readexactly(4))[0]
                    if not 1<=n<=limit_for(data):raise ValueError("invalid response")
                    return await reader.readexactly(n)
                finally:
                    writer.close()
                    try:await writer.wait_closed()
                    except OSError:pass

    async def __call__(self,data):
        return await self.exchange(data)

    async def snapshot(self):
        return await self.exchange(SNAPSHOT_OP,timeout=9)


def ru_serve():
    for path in (KEY,HOSTS):
        s=path.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077:
            raise ValueError("unsafe trust file")
    with subprocess.Popen(ssh_args(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,bufsize=0) as p:
        try:
            serve(p.stdout.fileno(),p.stdin.fileno())
        finally:
            if p.poll() is None:p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        if p.returncode not in (0,-15):raise ValueError("ssh ended")


if __name__=="__main__":
    try:
        os.umask(0o077)
        if os.geteuid()!=0:raise ValueError("root only")
        if sys.argv[1:]==["ru"] and "SSH_ORIGINAL_COMMAND" not in os.environ:
            ru_serve()
        elif len(sys.argv)==1 and os.environ.get("SSH_ORIGINAL_COMMAND")==COMMAND:
            fi_serve()
        else:raise ValueError("forced command only")
    except (OSError,ValueError,EOFError,TimeoutError,subprocess.SubprocessError):
        print("FI_DNS_REVERSE_CHANNEL_CLOSED",file=sys.stderr)
        raise SystemExit(2)
