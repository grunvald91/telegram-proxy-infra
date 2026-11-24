"""Persistent, pinned forced-command SSH channels on FI.

The SSH transport never forwards arbitrary ports and never invokes a shell.
Each operation uses one bounded serial channel; cancellation destroys the
channel so a delayed response cannot be reused by the next request.
"""
from __future__ import annotations
import asyncio
from pathlib import Path
import struct

from fi_dns_ssh_bridge import (COMMAND,MAX_REQUEST,MAX_SNAPSHOT,
                               PING_OP,PONG,SNAPSHOT_OP)


def ssh_args(identity: Path, known_hosts: Path):
    return [
        "/usr/bin/ssh","-F","/dev/null","-T",
        "-o","BatchMode=yes","-o","IdentitiesOnly=yes",
        "-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no",
        "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
        "-o","UserKnownHostsFile="+str(known_hosts),"-o","GlobalKnownHostsFile=/dev/null",
        "-o","UpdateHostKeys=no","-o","ForwardAgent=no","-o","ClearAllForwardings=yes",
        "-o","ControlMaster=no","-o","ProxyCommand=none",
        "-o","ConnectTimeout=4","-o","ServerAliveInterval=15","-o","ServerAliveCountMax=2",
        "-o","LogLevel=ERROR","-i",str(identity),"root@188.120.254.223",COMMAND,
    ]


class Channel:
    def __init__(self,args):
        self.args=tuple(args)
        self.process=None
        self.lock=asyncio.Lock()

    async def close(self):
        p=self.process
        self.process=None
        if p is None:return
        if p.stdin:p.stdin.close()
        if p.returncode is None:
            try:p.kill()
            except ProcessLookupError:pass
        try:await asyncio.wait_for(p.wait(),2)
        except asyncio.TimeoutError:pass

    async def exchange(self,data,*,timeout=2.2):
        if not isinstance(data,bytes) or not 1<=len(data)<=MAX_REQUEST:
            raise ValueError("invalid SSH request")
        limit=MAX_SNAPSHOT if data==SNAPSHOT_OP else MAX_REQUEST
        async with self.lock:
            try:
                async with asyncio.timeout(timeout):
                    if self.process is None or self.process.returncode is not None:
                        await self.close()
                        self.process=await asyncio.create_subprocess_exec(
                            *self.args,stdin=asyncio.subprocess.PIPE,
                            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
                            limit=MAX_SNAPSHOT+4)
                    p=self.process
                    p.stdin.write(struct.pack("!I",len(data))+data)
                    await p.stdin.drain()
                    n=struct.unpack("!I",await p.stdout.readexactly(4))[0]
                    if not 1<=n<=limit:raise ValueError("unsafe SSH reply")
                    return await p.stdout.readexactly(n)
            except BaseException:
                # Never replay a request automatically, especially a reserve.
                await self.close()
                raise


class MeterPool:
    def __init__(self,args,count=4):
        if type(count) is not int or not 1<=count<=8:raise ValueError("invalid pool size")
        self.channels=[Channel(args) for _ in range(count)]
        self.available=asyncio.Queue()
        for channel in self.channels:self.available.put_nowait(channel)
        self.snapshot_channel=Channel(args)

    async def warm(self):
        results=await asyncio.gather(*(
            channel.exchange(PING_OP,timeout=8) for channel in
            [*self.channels,self.snapshot_channel]))
        if any(value!=PONG for value in results):
            raise ValueError("untrusted bridge response")

    async def __call__(self,data):
        # QueryMeter already has a 3s outer timeout. Bound queue wait too.
        async with asyncio.timeout(2.7):
            channel=await self.available.get()
            try:return await channel.exchange(data)
            finally:self.available.put_nowait(channel)

    async def snapshot(self):
        return await self.snapshot_channel.exchange(SNAPSHOT_OP,timeout=8)

    async def close(self):
        await asyncio.gather(*(channel.close() for channel in
            [*self.channels,self.snapshot_channel]))
