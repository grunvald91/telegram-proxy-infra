#!/usr/bin/env python3
"""MNEBYVPN sealed stream format v1 (RSA-OAEP-SHA256 + AES-256-GCM).

Use:  python3 mnebyvpn_seal.py encrypt --public-key public.pem --output backup.mnebak < archive.tar
      python3 mnebyvpn_seal.py decrypt --private-key private-encrypted.pem --password-file passphrase.txt --input backup.mnebak --output archive.tar

Never put private keys, passphrases, unencrypted archives or service credentials in GitHub.
No plaintext is written during encryption. Decryption is staged to a private file
and atomically made visible only after a successful authenticated GCM tag check.
Requires Python 3.9+ and cryptography.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

MAGIC = b'MNEBYVPN-SEALED-V1\n'
HEADER_LIMIT = 32768
CHUNK = 1024 * 1024


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def atomic_target(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.mnebyvpn-seal-', dir=path.parent)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'wb'), Path(name)


def public_fp(pubkey) -> str:
    der = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def encrypt(pub_path: Path, out: Path):
    key = serialization.load_pem_public_key(pub_path.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError('Expected RSA >=3072-bit public key')
    if out.exists():
        raise FileExistsError('Refuse to overwrite existing backup')
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    wrapped = key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    header = json.dumps({'format':'MNEBYVPN-SEALED-V1', 'key_fingerprint_sha256':public_fp(key),
                         'encrypted_data_key':b64(wrapped), 'nonce':b64(nonce),
                         'cipher':'AES-256-GCM', 'key_wrap':'RSA-OAEP-SHA256'},sort_keys=True,separators=(',',':')).encode()
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).encryptor()
    f, tmp = atomic_target(out)
    try:
        with f:
            f.write(MAGIC)
            f.write(struct.pack('>I',len(header)))
            f.write(header)
            while True:
                chunk = sys.stdin.buffer.read(CHUNK)
                if not chunk: break
                f.write(encryptor.update(chunk))
            f.write(encryptor.finalize())
            f.write(encryptor.tag)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,out)
        print('encrypted_file_written=true')
        print('recipient_key_fingerprint_sha256='+public_fp(key))
    finally:
        if tmp.exists():tmp.unlink()


def decrypt(key_path: Path, password_file: Path, source: Path, out: Path):
    if out.exists():
        raise FileExistsError('Refuse to overwrite existing recovered plaintext')
    pwd = password_file.read_bytes().rstrip(b'\r\n')
    private = serialization.load_pem_private_key(key_path.read_bytes(),password=pwd)
    if not isinstance(private,rsa.RSAPrivateKey):
        raise ValueError('Expected RSA private key')
    with source.open('rb') as f:
        if f.read(len(MAGIC)) != MAGIC:raise ValueError('Unknown archive format')
        hs = f.read(4)
        if len(hs)!=4:raise ValueError('Truncated archive header')
        n = struct.unpack('>I',hs)[0]
        if n <= 0 or n > HEADER_LIMIT:raise ValueError('Invalid archive header length')
        header=json.loads(f.read(n))
        if header.get('format')!='MNEBYVPN-SEALED-V1':raise ValueError('Unexpected header')
        if header.get('cipher')!='AES-256-GCM' or header.get('key_wrap')!='RSA-OAEP-SHA256':raise ValueError('Unexpected cipher')
        if header.get('key_fingerprint_sha256')!=public_fp(private.public_key()):raise ValueError('Wrong recovery key')
        nonce=unb64(header['nonce'])
        if len(nonce)!=12:raise ValueError('Invalid nonce')
        aes_key=private.decrypt(unb64(header['encrypted_data_key']), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        if len(aes_key)!=32:raise ValueError('Invalid wrapped key')
        dec = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).decryptor()
        f.seek(0,os.SEEK_END)
        end=f.tell()
        pos=len(MAGIC)+4+n
        if end-pos<16:raise ValueError('Truncated ciphertext')
        cipherlen=end-pos-16
        f.seek(pos)
        wf, tmp=atomic_target(out)
        try:
            with wf:
                remaining=cipherlen
                while remaining:
                    chunk=f.read(min(CHUNK,remaining))
                    if not chunk:raise ValueError('Truncated ciphertext')
                    remaining-=len(chunk)
                    wf.write(dec.update(chunk))
                tag=f.read(16)
                if len(tag)!=16:raise ValueError('Missing authentication tag')
                wf.write(dec.finalize_with_tag(tag))
                wf.flush()
                os.fsync(wf.fileno())
            os.replace(tmp,out)
            print('authenticated_decryption=PASS')
        finally:
            if tmp.exists():tmp.unlink()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    e=sub.add_parser('encrypt');e.add_argument('--public-key',required=True,type=Path);e.add_argument('--output',required=True,type=Path)
    d=sub.add_parser('decrypt');d.add_argument('--private-key',required=True,type=Path);d.add_argument('--password-file',required=True,type=Path);d.add_argument('--input',required=True,type=Path);d.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    if args.action=='encrypt':encrypt(args.public_key,args.output)
    else:decrypt(args.private_key,args.password_file,args.input,args.output)

if __name__=='__main__':
    try:main()
    except (InvalidTag,ValueError,FileExistsError) as ex:
        print('ERROR: '+str(ex),file=sys.stderr)
        sys.exit(2)
