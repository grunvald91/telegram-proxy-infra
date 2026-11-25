#!/usr/bin/env python3
"""Bounded TCP relay. TLS and per-question entitlement/meter enforcement remain
in the existing loopback metered DoT runtime; never forward to raw CoreDNS.
"""
import asyncio
from collections import Counter
import os
import socket
import sys

PUBLIC_IP="217.11.167.91"
PUBLIC_PORT=853
BACKEND=("127.0.0.1",18854)
MAX_ACTIVE=48
MAX_PER_IP=8
IDLE=35
CHUNK=16384

async def close(writer):
    if writer is not None:
        writer.close()
        try:await asyncio.wait_for(writer.wait_closed(),2)
        except (OSError,asyncio.TimeoutError):pass

async def pipe(reader,writer):
    while True:
        data=await asyncio.wait_for(reader.read(CHUNK),IDLE)
        if not data:
            if writer.can_write_eof():
                writer.write_eof()
                await asyncio.wait_for(writer.drain(),2)
            return
        writer.write(data)
        await asyncio.wait_for(writer.drain(),5)

class Relay:
    def __init__(self):
        self.active=0
        self.ips=Counter()
    async def handle(self,reader,writer):
        peer=writer.get_extra_info("peername")
        if not peer:
            await close(writer);return
        ip=peer[0]
        if self.active>=MAX_ACTIVE or self.ips[ip]>=MAX_PER_IP:
            await close(writer);return
        self.active+=1;self.ips[ip]+=1
        upstream=None;jobs=[]
        try:
            incoming,upstream=await asyncio.wait_for(asyncio.open_connection(*BACKEND,limit=CHUNK*2),3)
            jobs=[asyncio.create_task(pipe(reader,upstream)),asyncio.create_task(pipe(incoming,writer))]
            done,pending=await asyncio.wait(jobs,return_when=asyncio.FIRST_COMPLETED)
            for task in done:task.result()
            # Preserve final TLS records on clean half-close, but bound wait.
            if pending:await asyncio.wait(pending,timeout=2)
        except (OSError,asyncio.TimeoutError):pass
        finally:
            for task in jobs:task.cancel()
            await asyncio.gather(*jobs,return_exceptions=True)
            await close(upstream);await close(writer)
            self.active-=1;self.ips[ip]-=1
            if not self.ips[ip]:del self.ips[ip]

def activated_socket():
    if os.environ.get("LISTEN_PID")!=str(os.getpid()) or os.environ.get("LISTEN_FDS")!="1":
        raise RuntimeError("exactly_one_systemd_socket_required")
    sock=socket.socket(fileno=3)
    if sock.family!=socket.AF_INET or sock.type!=socket.SOCK_STREAM or sock.getsockname()!=(PUBLIC_IP,PUBLIC_PORT) or not sock.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN):
        sock.close();raise RuntimeError("unexpected_listener")
    os.set_inheritable(sock.fileno(),False)
    return sock

async def main():
    sock=activated_socket()
    relay=Relay()
    server=await asyncio.start_server(relay.handle,sock=sock,limit=CHUNK*2,backlog=64)
    print("FI_PUBLIC_DOT_RELAY_READY=true",flush=True)
    async with server:await server.serve_forever()

if __name__=="__main__":
    try:asyncio.run(main())
    except (OSError,RuntimeError,ValueError):
        print("FI_PUBLIC_DOT_RELAY_FAILED=true",file=sys.stderr)
        raise SystemExit(2)
