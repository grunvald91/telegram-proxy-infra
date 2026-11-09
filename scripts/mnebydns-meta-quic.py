#!/usr/bin/env python3
"""Isolated Meta-only QUIC v1 UDP relay through existing RU<->DE WireGuard.

Roles:
  ru: public UDP/443 -> 10.66.77.1:19444 via dedicated per-flow sockets
  de: private UDP/19444 -> resolved public Meta origin:443

No TLS interception. No reusable arbitrary UDP proxy: every new flow is
admitted only after parsing QUIC Initial / TLS ClientHello SNI and a strict
Meta allowlist. QUIC v2 or unparseable Initials fail closed.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INITIAL_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
META_SUFFIXES = (
    "instagram.com", "cdninstagram.com", "instagr.am", "ig.me",
    "igsonar.com", "threads.com", "threads.net", "facebook.com",
    "facebook.net", "fbcdn.net", "fbsbx.com", "fb.com", "meta.com",
    "meta.ai", "instagramstatic.com", "igcdn.com", "fbcdn.com",
)
META_EXACT = frozenset(("instagramstatic-a.akamaihd.net",))
MAX_DATAGRAM = 1450
MAX_FLOWS = 128
IDLE_SECONDS = 65


def allowed(name: Optional[str]) -> bool:
    if not name or len(name) > 253 or name.lower() != name:
        return False
    return name in META_EXACT or any(name == z or name.endswith("." + z) for z in META_SUFFIXES)


def hkdf_expand(secret: bytes, info: bytes, size: int) -> bytes:
    result = b""
    prev = b""
    i = 1
    while len(result) < size:
        prev = hmac.new(secret, prev + info + bytes([i]), hashlib.sha256).digest()
        result += prev
        i += 1
    return result[:size]


def quic_label(secret: bytes, name: str, size: int) -> bytes:
    label = b"tls13 " + name.encode("ascii")
    info = struct.pack("!H", size) + bytes((len(label),)) + label + b"\x00"
    return hkdf_expand(secret, info, size)


def varint(data: bytes, start: int) -> tuple[int, int]:
    if start >= len(data):
        raise ValueError("truncated varint")
    n = 1 << (data[start] >> 6)
    if start + n > len(data):
        raise ValueError("truncated varint")
    val = data[start] & 63
    for j in range(1, n):
        val = (val << 8) | data[start + j]
    return val, start + n


def tls_hello_sni(hello: bytes) -> Optional[str]:
    if len(hello) < 46 or hello[0] != 1:
        return None
    length = int.from_bytes(hello[1:4], "big")
    if length + 4 > len(hello) or length > 8192:
        return None
    body = hello[4:4 + length]
    offset = 34  # legacy version and client random
    try:
        session_len = body[offset]; offset += 1 + session_len
        ciphers = int.from_bytes(body[offset:offset+2], "big"); offset += 2 + ciphers
        comp = body[offset]; offset += 1 + comp
        ext_len = int.from_bytes(body[offset:offset+2], "big"); offset += 2
        end = offset + ext_len
        if end > len(body):
            return None
        while offset + 4 <= end:
            typ, n = struct.unpack("!HH", body[offset:offset+4]); offset += 4
            extension = body[offset:offset+n]; offset += n
            if typ == 0:
                if len(extension) < 5 or extension[2] != 0:
                    return None
                n = int.from_bytes(extension[3:5], "big")
                if 5+n > len(extension):
                    return None
                return extension[5:5+n].decode("ascii").lower()
    except (IndexError, ValueError, UnicodeDecodeError):
        return None
    return None


def initial_sni(packet: bytes) -> Optional[str]:
    """Extract SNI from one complete QUIC v1 Initial containing CRYPTO at offset 0.

    No application data or TLS traffic is decrypted: only public Initial keys
    and the ClientHello are processed, as defined in RFC 9001.
    """
    if len(packet) < 1200 or len(packet) > MAX_DATAGRAM:
        return None
    if packet[0] & 0xf0 not in (0xc0,):  # long header, fixed bit, Initial v1
        return None
    if packet[1:5] != b"\x00\x00\x00\x01":
        return None
    try:
        pos = 5
        dcid_len = packet[pos]
        pos += 1
        if not (1 <= dcid_len <= 20): return None
        dcid = packet[pos:pos+dcid_len]
        pos += dcid_len
        scid_len = packet[pos]
        pos += 1 + scid_len
        if scid_len > 20: return None
        token_len, pos = varint(packet, pos)
        if token_len > 512: return None
        pos += token_len
        frame_len, pos = varint(packet, pos)
        if frame_len < 20 or pos + frame_len > len(packet): return None
        pn_offset = pos
        initial_secret = hmac.new(INITIAL_V1_SALT, dcid, hashlib.sha256).digest()
        client_secret = quic_label(initial_secret, "client in", 32)
        key = quic_label(client_secret, "quic key", 16)
        iv = quic_label(client_secret, "quic iv", 12)
        hp = quic_label(client_secret, "quic hp", 16)
        sample = packet[pn_offset + 4:pn_offset + 20]
        cipher = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = cipher.update(sample) + cipher.finalize()
        first_byte = packet[0] ^ (mask[0] & 15)
        pn_len = (first_byte & 3) + 1
        pn_bytes = bytes(packet[pn_offset+j] ^ mask[1+j] for j in range(pn_len))
        packet_number = int.from_bytes(pn_bytes, "big")
        associated = bytes((first_byte,)) + packet[1:pn_offset] + pn_bytes
        nonce = bytes(a ^ b for a,b in zip(iv, packet_number.to_bytes(12, "big")))
        plain = AESGCM(key).decrypt(nonce, packet[pn_offset+pn_len:pn_offset+frame_len], associated)
        offset = 0
        # PADDING (0x00) and CRYPTO (0x06) are sufficient for the observed PCAPs.
        while offset < len(plain):
            typ = plain[offset]; offset += 1
            if typ == 0: continue
            if typ != 6: return None
            crypto_offset, offset = varint(plain, offset)
            length, offset = varint(plain, offset)
            if length > 8192 or offset + length > len(plain):return None
            if crypto_offset == 0:
                return tls_hello_sni(plain[offset:offset+length])
            offset += length
    except (ValueError, IndexError, InvalidTag, OverflowError):
        return None
    return None


def public_ipv4(name: str) -> str:
    # Use the host's normal resolver, NOT MNEBYDNS synthetic DoT.
    results = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_DGRAM)
    for r in results:
        ip = r[4][0]
        if ipaddress.ip_address(ip).is_global and ip not in ("188.120.254.223", "89.125.90.101"):
            return ip
    raise ValueError("no safe public IPv4 origin")


@dataclass
class Flow:
    transport: asyncio.DatagramTransport | None = None
    pending: list[bytes] = field(default_factory=list)
    last: float = field(default_factory=time.monotonic)


class ConnectedDatagram(asyncio.DatagramProtocol):
    def __init__(self, router: "MetaRouter", client: tuple[str, int]):
        self.router = router
        self.client = client

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        flow = self.router.flows.get(self.client)
        if flow:
            flow.last = time.monotonic()
            self.router.transport.sendto(data, self.client)

    def error_received(self, exc):
        self.router.discard(self.client)


class MetaRouter(asyncio.DatagramProtocol):
    def __init__(self, role: str, peer: str, listen_ip: str):
        self.role, self.peer, self.listen_ip = role, peer, listen_ip
        self.transport = None
        self.flows: dict[tuple[str, int], Flow] = {}
        self.counters = {"admitted":0, "rejected":0, "expired":0, "resolve_error":0}

    def connection_made(self, transport):
        self.transport = transport
        print(f"meta_quic_{self.role}_udp_listener_ready=true",flush=True)
        asyncio.create_task(self.housekeeping())

    def discard(self, client: tuple[str,int]):
        flow=self.flows.pop(client,None)
        if flow and flow.transport:
            flow.transport.close()

    def datagram_received(self, packet: bytes, source: tuple[str,int]):
        if len(packet)>MAX_DATAGRAM or len(packet)<20: return
        if self.role=='de' and source[0] != self.peer: return
        flow=self.flows.get(source)
        if flow:
            flow.last=time.monotonic()
            if flow.transport: flow.transport.sendto(packet)
            elif len(flow.pending)<8:flow.pending.append(packet)
            return
        if len(self.flows)>=MAX_FLOWS:return
        name=initial_sni(packet)
        if not allowed(name):
            self.counters['rejected']+=1
            return
        flow=Flow(pending=[packet]);self.flows[source]=flow
        asyncio.create_task(self.establish(source,name,flow))

    async def establish(self, source: tuple[str,int], name: str, flow: Flow):
        try:
            if self.role=='ru':
                host,port='10.66.77.1',19444
                bind=('0.0.0.0',0)
            else:
                host=await asyncio.to_thread(public_ipv4,name)
                port=443
                bind=('0.0.0.0',0)
            loop=asyncio.get_running_loop()
            transport,_=await loop.create_datagram_endpoint(lambda:ConnectedDatagram(self,source),local_addr=bind,remote_addr=(host,port))
            if self.flows.get(source) is not flow:
                transport.close();return
            flow.transport=transport
            for item in flow.pending:transport.sendto(item)
            flow.pending.clear()
            self.counters['admitted']+=1
        except Exception:
            self.counters['resolve_error']+=1
            self.discard(source)

    async def housekeeping(self):
        while True:
            await asyncio.sleep(12)
            now=time.monotonic()
            for addr,flow in list(self.flows.items()):
                if now-flow.last>IDLE_SECONDS:
                    self.discard(addr)
                    self.counters['expired']+=1
            print('meta_quic_'+self.role+'_active='+str(len(self.flows))+' '+
                  ' '.join(f'{k}={v}' for k,v in self.counters.items()),flush=True)


async def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--role',choices=('ru','de'),required=True)
    parser.add_argument('--bind',required=True)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--peer',required=True)
    args=parser.parse_args()
    if args.role=='de' and (args.bind!='10.66.77.1' or args.peer!='10.66.77.2' or args.port!=19444):
        parser.error('DE role must use private WG bind and trusted RU peer')
    if args.role=='ru' and (args.port!=443 or args.peer!='10.66.77.1'):
        parser.error('RU role must use public 443 and DE WG address')
    loop=asyncio.get_running_loop()
    transport,_=await loop.create_datagram_endpoint(lambda:MetaRouter(args.role,args.peer,args.bind),local_addr=(args.bind,args.port))
    try:await asyncio.Event().wait()
    finally:transport.close()


if __name__=='__main__':
    asyncio.run(main())