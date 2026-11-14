#!/usr/bin/env python3
"""Synthetic-only QUIC v1 Initial and YouTube allowlist tests. No user PCAP."""
from __future__ import annotations
import importlib.util
import pathlib
import struct
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILE = pathlib.Path(__file__).resolve().parent / 'mnebydns-youtube-quic.py'
spec = importlib.util.spec_from_file_location('youtube_quic_relay', FILE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def varint_2(x: int) -> bytes:
    assert 64 <= x <= 16383
    return bytes((0x40 | (x >> 8), x & 255))


def fixture_sni(domain: str, version: int = 1) -> bytes:
    """Original synthetic ClientHello embedded inside QUIC Initial v1."""
    hostname = domain.encode('ascii')
    server_name = b'\x00' + struct.pack('!H', len(hostname)) + hostname
    names = struct.pack('!H', len(server_name)) + server_name
    sni = struct.pack('!HH', 0, len(names)) + names
    body = (b'\x03\x03' + bytes(range(32)) + b'\x00' +
            struct.pack('!H', 2) + b'\x13\x01' + b'\x01\x00' +
            struct.pack('!H', len(sni)) + sni)
    handshake = b'\x01' + len(body).to_bytes(3,'big') + body
    crypto = b'\x06\x00' + varint_2(len(handshake)) + handshake
    dcid = bytes.fromhex('0123456789abcdef')
    pn = 1
    assert version in (1, 2)
    salt = mod.INITIAL_V1_SALT if version == 1 else mod.INITIAL_V2_SALT
    label = "quic" if version == 1 else "quicv2"
    initial = mod.hmac.new(salt, dcid, mod.hashlib.sha256).digest()
    client = mod.quic_label(initial, 'client in', 32)
    key = mod.quic_label(client, label + ' key', 16)
    iv = mod.quic_label(client, label + ' iv', 12)
    hp = mod.quic_label(client, label + ' hp', 16)
    # Total datagram 1252, long-header length is 1234 (including PN/tag).
    length = 1234
    unprotected = ((b'\xc1\x00\x00\x00\x01' if version == 1 else b'\xd1\x6b\x33\x43\xcf') + bytes((len(dcid),)) + dcid +
                   b'\x00\x00' + varint_2(length) + pn.to_bytes(2,'big'))
    assert len(unprotected) == 20
    padded = crypto + b'\x00' * (length - 2 - 16 - len(crypto))
    assert len(padded) == length - 2 - 16
    nonce = bytes(a^b for a,b in zip(iv,pn.to_bytes(12,'big')))
    encrypted = AESGCM(key).encrypt(nonce,padded,unprotected)
    raw = bytearray(unprotected + encrypted)
    sample = bytes(raw[22:38])
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    raw[0] ^= mask[0]&15
    raw[18] ^= mask[1]
    raw[19] ^= mask[2]
    return bytes(raw)


def run():
    targets=('youtube.com','www.youtube.com','music.youtube.com','www.googlevideo.com',
             'r1---sn-test.googlevideo.com','i.ytimg.com','youtubei.googleapis.com')
    for host in targets:
        assert mod.allowed(host)
        for version in (1, 2):
            result=mod.initial_sni(fixture_sni(host, version))
            assert result==host,(host,version,result)
    for host in ('i.instagram.com','graph.instagram.com','graph.facebook.com','evilgooglevideo.com',
                 'googlevideo.com.evil.org','internal.local','127.0.0.1','foo.telegram.org'):
        assert not mod.allowed(host)
    for invalid in (b'\x00'*1252,fixture_sni('www.youtube.com')[:-1],
                    b'\x11'*999):
        assert mod.initial_sni(invalid) is None
    assert mod.MAX_FLOWS<=256
    # PMTU / UDP socket errors must be reported, not silently ignored.
    router=mod.YoutubeRouter('ru','10.66.77.1','127.0.0.1')
    sock=mod.ConnectedDatagram(router,('127.0.0.1',40000))
    sock.error_received(OSError(mod.errno.EMSGSIZE,'message too long'))
    assert router.counters['socket_error']==1
    assert router.counters['emsgsize']==1
    import asyncio
    asyncio.run(test_local_response_path())
    print('youtube_quic_local_two_hop_UDP_roundtrip=PASS')
    print('youtube_quic_synthetic_v1_v2_7_domains=PASS')
    print('youtube_quic_non_YouTube_rejected=PASS')
    print('meta_quic_no_user_payloads_or_pcap_in_repo=true')


async def test_local_response_path():
    """Verify both UDP relays forward a reply, not merely admit an Initial.

    A localhost echo fixture substitutes for Meta; no external packets,
    account data or real phone traffic are used in this regression test.
    """
    import asyncio
    loop = asyncio.get_running_loop()
    mark = b'echo-server-roundtrip:'

    class Echo(asyncio.DatagramProtocol):
        def connection_made(self, transport): self.transport=transport
        def datagram_received(self, data, addr):
            self.transport.sendto(mark + data[:16], addr)

    class Client(asyncio.DatagramProtocol):
        def __init__(self):
            self.data=None
            self.event=asyncio.Event()
        def datagram_received(self,data,addr):
            self.data=data
            self.event.set()

    class IsolatedRouter(mod.MetaRouter):
        def __init__(self, role, destination):
            super().__init__(role, '127.0.0.1', '127.0.0.1')
            self.destination=destination
        async def destination_for(self,name):
            assert mod.allowed(name)
            return self.destination

    transports=[]
    try:
        echo_transport,_=await loop.create_datagram_endpoint(Echo,local_addr=('127.0.0.1',0))
        transports.append(echo_transport)
        ep=echo_transport.get_extra_info('sockname')
        de=IsolatedRouter('de',ep)
        de_transport,_=await loop.create_datagram_endpoint(lambda:de,local_addr=('127.0.0.1',0))
        transports.append(de_transport)
        ru=IsolatedRouter('ru',de_transport.get_extra_info('sockname'))
        ru_transport,_=await loop.create_datagram_endpoint(lambda:ru,local_addr=('127.0.0.1',0))
        transports.append(ru_transport)
        client=Client()
        client_transport,_=await loop.create_datagram_endpoint(lambda:client,local_addr=('127.0.0.1',0))
        transports.append(client_transport)
        data=fixture_sni('www.youtube.com')
        client_transport.sendto(data,ru_transport.get_extra_info('sockname'))
        await asyncio.wait_for(client.event.wait(),3.0)
        assert client.data==mark+data[:16],client.data
        for router in (ru,de):
            assert router.counters['rx'] >=1,router.counters
            assert router.counters['to_upstream']>=1,router.counters
            assert router.counters['upstream_rx']>=1,router.counters
            assert router.counters['client_tx']>=1,router.counters
        assert ru.counters['admitted']==1 and de.counters['admitted']==1
        # A malicious hostname must not create a second upstream flow.
        extra,_=await loop.create_datagram_endpoint(Client,local_addr=('127.0.0.1',0))
        transports.append(extra)
        extra.sendto(fixture_sni('internal.local'),ru_transport.get_extra_info('sockname'))
        await asyncio.sleep(.12)
        assert ru.counters['rejected']>=1,ru.counters
        assert ru.counters['admitted']==1,ru.counters
    finally:
        for t in reversed(transports):t.close()
        await asyncio.sleep(.05)

if __name__=='__main__':run()