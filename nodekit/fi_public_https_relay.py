#!/usr/bin/env python3
"""Bounded IPv4 TCP frontend for the existing guarded FI HTTPS backend."""
import asyncio
from collections import Counter
import os
import socket

ADDRESS = ("217.11.167.91", 443)
BACKEND = ("127.0.0.1", 14443)
MAX_ACTIVE = 256
MAX_PER_IP = 32
CHUNK = 65536
IDLE = 90

async def close(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 3)
        except (OSError, asyncio.TimeoutError):
            pass

class Relay:
    def __init__(self):
        self.active = 0
        self.ips = Counter()

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        if not peer or self.active >= MAX_ACTIVE or self.ips[peer[0]] >= MAX_PER_IP:
            await close(writer)
            return
        ip = peer[0]
        self.active += 1
        self.ips[ip] += 1
        upstream = None
        tasks = []
        loop = asyncio.get_running_loop()
        last = loop.time()

        async def pipe(source, target):
            nonlocal last
            while True:
                data = await source.read(CHUNK)
                if not data:
                    if target.can_write_eof():
                        target.write_eof()
                        await asyncio.wait_for(target.drain(), 10)
                    return
                last = loop.time()
                target.write(data)
                await asyncio.wait_for(target.drain(), 30)
                last = loop.time()

        async def watchdog():
            while True:
                await asyncio.sleep(5)
                if loop.time() - last >= IDLE:
                    raise asyncio.TimeoutError()

        try:
            incoming, upstream = await asyncio.wait_for(
                asyncio.open_connection(*BACKEND, limit=CHUNK), 5)
            tasks = [asyncio.create_task(pipe(reader, upstream)),
                     asyncio.create_task(pipe(incoming, writer)),
                     asyncio.create_task(watchdog())]
            pending = set(tasks)
            while any(t in pending for t in tasks[:2]):
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    t.result()
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await close(upstream)
            await close(writer)
            self.active -= 1
            self.ips[ip] -= 1
            if not self.ips[ip]:
                del self.ips[ip]

async def main():
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("socket activation required")
    sock = socket.socket(fileno=3)
    if sock.family != socket.AF_INET or sock.type != socket.SOCK_STREAM or sock.getsockname() != ADDRESS or not sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
        sock.close()
        raise RuntimeError("unexpected listener")
    os.set_inheritable(sock.fileno(), False)
    relay = Relay()
    server = await asyncio.start_server(relay.handle, sock=sock, limit=CHUNK, backlog=128)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
