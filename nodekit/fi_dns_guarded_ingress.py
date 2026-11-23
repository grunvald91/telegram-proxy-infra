#!/usr/bin/env python3
"""Non-published FI217 personal DoT SNI guard for a local CoreDNS TLS origin.

No automatic installation, systemd unit, firewalls, public sockets or buyers.
Even if started deliberately, this guard only binds 127.0.0.1:18853.
A separate reviewed publication path must first prove wildcard DNS-01 TLS,
paid query metering, signed grants, rollbacks and Android external E2E.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
import json
from pathlib import Path
import socket
import ssl
import sys
import time

from fi_dns_signed_grants import (
    RegionalDnsGrantError, hostname_digest, load, authorized,
)

NODE = "fi-test-01"
ROOT = Path("/var/lib/mnebyvpn-nodekit") / NODE
SNAPSHOT = ROOT / "dns-auth" / "snapshot.json"
CONTROLLER = ROOT / "controller-access.spki"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 18853
CORE_IP = "127.0.0.1"
CORE_PORT = 8853
PRELUDE_MAX = 65536
TIMEOUT_SEC = 4
MAX_GLOBAL_CONNECTIONS = 64
MAX_PER_CREDENTIAL = 4
PROBE_A = "aaaaaaaaaaaa.fi.dns.mnebyvpn.site"
PROBE_B = "bbbbbbbbbbbb.fi.dns.mnebyvpn.site"


class IncompleteHello(Exception):
    pass


class DnsIngressError(ValueError):
    pass


def deny() -> None:
    raise DnsIngressError("Invalid or unapproved TLS ClientHello")


def name_from_client_hello(raw: bytes) -> str:
    """Parse SNI in fragmented TLS handshake records, never plaintext DNS."""
    if not isinstance(raw, bytes) or len(raw) > PRELUDE_MAX:
        deny()
    pos = 0
    handshake = bytearray()
    while pos < len(raw):
        if len(raw) - pos < 5:
            raise IncompleteHello()
        content_type, major, minor = raw[pos:pos+3]
        if content_type != 22 or major != 3 or minor not in (1, 2, 3, 4):
            deny()
        n = int.from_bytes(raw[pos+3:pos+5], "big")
        if not 1 <= n <= 16384:
            deny()
        if len(raw) - pos < 5 + n:
            raise IncompleteHello()
        handshake.extend(raw[pos+5:pos+5+n])
        if len(handshake) >= 4:
            if handshake[0] != 1:
                deny()
            wanted = int.from_bytes(handshake[1:4], "big")
            if not 42 <= wanted <= PRELUDE_MAX - 5:
                deny()
            if len(handshake) >= wanted + 4:
                return _parse_sni(bytes(handshake[4:4+wanted]))
        pos += 5 + n
    raise IncompleteHello()


def _parse_sni(hello: bytes) -> str:
    def take(p: int, n: int) -> tuple[bytes, int]:
        if n < 0 or p + n > len(hello):
            deny()
        return hello[p:p+n], p+n

    if len(hello) < 41 or hello[0] != 3 or hello[1] not in (1, 2, 3):
        deny()
    p = 34  # legacy_version + 32 byte random
    ident_len, p = take(p, 1)
    _, p = take(p, ident_len[0])
    cipher_len, p = take(p, 2)
    count = int.from_bytes(cipher_len, "big")
    if count < 2 or count & 1:
        deny()
    _, p = take(p, count)
    compression_len, p = take(p, 1)
    _, p = take(p, compression_len[0])
    extension_len, p = take(p, 2)
    total = int.from_bytes(extension_len, "big")
    if total != len(hello) - p:
        deny()
    end = p + total
    found: str | None = None
    while p < end:
        if end - p < 4:
            deny()
        kind = int.from_bytes(hello[p:p+2], "big")
        size = int.from_bytes(hello[p+2:p+4], "big")
        p += 4
        if size > end - p:
            deny()
        value = hello[p:p+size]
        p += size
        if kind != 0:
            continue
        if found is not None or size < 5 or int.from_bytes(value[:2], "big") != size-2:
            deny()
        cursor = 2
        while cursor < size:
            if size - cursor < 3:
                deny()
            nametype = value[cursor]
            namelen = int.from_bytes(value[cursor+1:cursor+3], "big")
            cursor += 3
            if nametype != 0 or not 1 <= namelen <= 253 or cursor + namelen > size or found:
                deny()
            try:
                found = value[cursor:cursor+namelen].decode("ascii")
            except UnicodeDecodeError:
                deny()
            cursor += namelen
    if found is None:
        deny()
    # Only country-scoped, 12-character FI bearer SNI is a supported identity.
    try:
        hostname_digest(found)
    except RegionalDnsGrantError:
        deny()
    return found


async def prelude(reader: asyncio.StreamReader) -> tuple[str, bytes]:
    pending = bytearray()
    started = time.monotonic()
    while len(pending) < PRELUDE_MAX:
        left = TIMEOUT_SEC - (time.monotonic() - started)
        if left <= 0:
            deny()
        data = await asyncio.wait_for(
            reader.read(min(4096, PRELUDE_MAX - len(pending))), timeout=left)
        if not data:
            deny()
        pending.extend(data)
        try:
            return name_from_client_hello(bytes(pending)), bytes(pending)
        except IncompleteHello:
            continue
    deny()


def verify_local_origin() -> None:
    """A staged fi.mnebyvpn.site leaf is NOT enough for personal FI SNI."""
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    for name in (PROBE_A, PROBE_B):
        with socket.create_connection((CORE_IP, CORE_PORT), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=name) as tls:
                if tls.version() not in ("TLSv1.2", "TLSv1.3"):
                    raise DnsIngressError("Untrusted CoreDNS TLS protocol")
    # A passing TLS handshake does not prove DNS query correctness or egress.


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                deadline: float) -> None:
    while True:
        remain = deadline - time.time()
        if remain <= 0:
            return
        block = await asyncio.wait_for(reader.read(16_384), timeout=remain)
        if not block:
            return
        writer.write(block)
        await asyncio.wait_for(writer.drain(), timeout=min(remain, 5))


class Guard:
    def __init__(self, expected_controller_sha: str):
        self.pin = expected_controller_sha
        self.connections: Counter[str] = Counter()
        self.total = 0
        self.last_revision = 0

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        digest: str | None = None
        upwriter: asyncio.StreamWriter | None = None
        self.total += 1
        try:
            if self.total > MAX_GLOBAL_CONNECTIONS:
                return
            name, buffered = await prelude(reader)
            snapshot = load(SNAPSHOT, CONTROLLER, self.pin)
            if snapshot["revision"] < self.last_revision:
                return
            self.last_revision = snapshot["revision"]
            ok, expires = authorized(snapshot, name)
            if not ok:
                return
            digest = hostname_digest(name)
            if self.connections[digest] >= MAX_PER_CREDENTIAL:
                return
            self.connections[digest] += 1
            # This is TLS passthrough. CoreDNS must offer the *same* wildcard
            # TLS certificate checked at startup. The application never
            # decrypts or logs customers' DNS queries.
            upreader, upwriter = await asyncio.wait_for(
                asyncio.open_connection(CORE_IP, CORE_PORT), timeout=3)
            upwriter.write(buffered)
            await asyncio.wait_for(upwriter.drain(), timeout=3)
            # Even persistent DoT sockets are closed at signed-snapshot expiry.
            jobs = [
                asyncio.create_task(_pipe(reader, upwriter, expires)),
                asyncio.create_task(_pipe(upreader, writer, expires)),
            ]
            try:
                done, pending = await asyncio.wait(
                    jobs, timeout=max(0, expires-time.time()),
                    return_when=asyncio.FIRST_COMPLETED)
                for job in done:
                    try:
                        job.result()
                    except (OSError, asyncio.TimeoutError):
                        pass
            finally:
                for job in jobs:
                    job.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
        except (DnsIngressError, RegionalDnsGrantError, OSError,
                ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            if digest is not None and self.connections[digest] > 0:
                self.connections[digest] -= 1
                if self.connections[digest] == 0:
                    del self.connections[digest]
            self.total -= 1
            if upwriter is not None:
                upwriter.close()
                try:
                    await asyncio.wait_for(upwriter.wait_closed(), timeout=2)
                except (OSError, asyncio.TimeoutError):
                    pass
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (OSError, asyncio.TimeoutError):
                pass


async def serve(sha: str) -> None:
    # Root-only key and signed grants, local-only interface, no public 853.
    policy = load(SNAPSHOT, CONTROLLER, sha)
    if not policy["grants"]:
        raise DnsIngressError("No verified FI grants staged")
    verify_local_origin()
    guard = Guard(sha)
    server = await asyncio.start_server(
        guard.handle, host=LISTEN_IP, port=LISTEN_PORT,
        limit=PRELUDE_MAX)
    async with server:
        await server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-sha256", required=True)
    parser.add_argument("--mode", choices=("inspect", "serve"), default="inspect")
    args = parser.parse_args()
    try:
        p = load(SNAPSHOT, CONTROLLER, args.controller_sha256)
        if args.mode == "inspect":
            print(json.dumps({"node_id": NODE, "signed_policy_valid": True,
                              "grant_count": len(p["grants"]),
                              "public_listener_enabled": False,
                              "production_ready": False}, sort_keys=True))
        else:
            asyncio.run(serve(args.controller_sha256))
        return 0
    except (OSError, ValueError, TypeError, ssl.SSLError):
        print("FI_DOT_SIGNED_INGRESS_NOT_READY=true", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
