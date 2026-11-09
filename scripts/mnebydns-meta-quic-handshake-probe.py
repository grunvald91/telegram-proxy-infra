#!/usr/bin/env python3
"""Active certificate-verified QUIC v1 handshake probe via direct or RU path.

Uses aioquic in a disposable GitHub runner environment. No HTTP requests,
credentials or user data. Results represent the runner's path, NOT the phone's.
"""
from __future__ import annotations
import argparse
import asyncio
import logging
import socket
import ssl
import time

# Avoid exception traces from aioquic containing sensitive peer metadata.
logging.getLogger('aioquic').setLevel(logging.CRITICAL)

TARGETS = ('i.instagram.com','i-fallback.instagram.com','test-gateway.instagram.com',
           'threads.com','graph.instagram.com')
RU = '188.120.254.223'


async def probe(host: str, destination: str) -> tuple[str,int]:
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.packet import QuicProtocolVersion

    cfg=QuicConfiguration(is_client=True, alpn_protocols=['h3','h3-29'],
                          server_name=host, verify_mode=ssl.CERT_REQUIRED,
                          supported_versions=[QuicProtocolVersion.VERSION_1])
    started=time.monotonic()
    async with connect(destination,443,configuration=cfg,wait_connected=True):
        return 'verified_quic_handshake',round(1000*(time.monotonic()-started))


async def main():
    p=argparse.ArgumentParser()
    p.add_argument('--mode',choices=('direct','ru'),required=True)
    p.add_argument('--timeout',type=float,default=6.0)
    args=p.parse_args()
    if not 1 <= args.timeout <= 15:
        raise SystemExit('timeout 1..15 seconds')
    for host in TARGETS:
        if args.mode=='ru': dst=RU
        else:
            try:
                answers=socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_DGRAM)
                dst=answers[0][4][0]
            except Exception as exc:
                print(f'QUIC_{args.mode}_{host}=DNS_{type(exc).__name__}',flush=True)
                continue
        try:
            result,ms=await asyncio.wait_for(probe(host,dst),timeout=args.timeout)
            print(f'QUIC_{args.mode}_{host}={result} elapsed_ms={ms}',flush=True)
        except Exception as exc:
            print(f'QUIC_{args.mode}_{host}={type(exc).__name__}',flush=True)
    print('QUIC_source_is_GitHub_runner_NOT_mobile_network=true',flush=True)

if __name__=='__main__':asyncio.run(main())