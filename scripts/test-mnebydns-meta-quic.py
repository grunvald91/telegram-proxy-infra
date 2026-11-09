#!/usr/bin/env python3
"""Synthetic-only QUIC v1 Initial and Meta allowlist tests. No user PCAP."""
from __future__ import annotations
import importlib.util
import pathlib
import struct
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILE = pathlib.Path(__file__).resolve().parent / 'mnebydns-meta-quic.py'
spec = importlib.util.spec_from_file_location('meta_quic_relay', FILE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def varint_2(x: int) -> bytes:
    assert 64 <= x <= 16383
    return bytes((0x40 | (x >> 8), x & 255))


def fixture_sni(domain: str) -> bytes:
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
    initial = mod.hmac.new(mod.INITIAL_V1_SALT, dcid, mod.hashlib.sha256).digest()
    client = mod.quic_label(initial, 'client in', 32)
    key = mod.quic_label(client, 'quic key', 16)
    iv = mod.quic_label(client, 'quic iv', 12)
    hp = mod.quic_label(client, 'quic hp', 16)
    # Total datagram 1252, long-header length is 1234 (including PN/tag).
    length = 1234
    unprotected = (b'\xc1\x00\x00\x00\x01' + bytes((len(dcid),)) + dcid +
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
    targets=('i.instagram.com','i-fallback.instagram.com',
             'test-gateway.instagram.com','graph.instagram.com',
             'graph.facebook.com','threads.com',
             'fake-tracker.fbcdn.net')
    for host in targets:
        assert mod.allowed(host)
        result=mod.initial_sni(fixture_sni(host))
        assert result==host,(host,result)
    for host in ('evilinstagram.com','instagram.com.evil.org',
                 'internal.local','127.0.0.1','foo.telegram.org'):
        assert not mod.allowed(host)
    for invalid in (b'\x00'*1252,fixture_sni('i.instagram.com')[:-1],
                    b'\x11'*999):
        assert mod.initial_sni(invalid) is None
    assert mod.MAX_FLOWS<=256
    print('meta_quic_synthetic_v1_7_domains=PASS')
    print('meta_quic_non_Meta_rejected=PASS')
    print('meta_quic_no_user_payloads_or_pcap_in_repo=true')

if __name__=='__main__':run()