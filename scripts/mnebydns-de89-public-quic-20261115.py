#!/usr/bin/env python3
"""Public DE89 QUIC listener for the EXISTING allowlisted YouTube/Google relay.

This is a separate UDP/443 ingress on the DE host. It imports the already
deployed, verified relay parser; it does not change the private WG:19444
service, TCP/443, CoreDNS, Docker, subscriber data, or any firewall rules.
"""
from __future__ import annotations
import asyncio
import hashlib
import importlib.util
import pathlib
import sys

PUBLIC_IP = "89.125.90.101"
PUBLIC_PORT = 443
RELAY = pathlib.Path("/opt/mnebydns-youtube-quic-43612369808/relay.py")
RELAY_SHA256 = "bde13ba42945a6489c7fdc235996ff9858961bde27e2881759dc24112122d46f"

def load_pinned_relay():
    if not RELAY.is_file() or RELAY.is_symlink():
        raise RuntimeError("Existing verified QUIC relay file not present")
    if hashlib.sha256(RELAY.read_bytes()).hexdigest() != RELAY_SHA256:
        raise RuntimeError("Existing QUIC code drift; public DE ingress is NOT approved")
    spec = importlib.util.spec_from_file_location("existing_youtube_quic_relay", RELAY)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot import existing QUIC relay")
    relay = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = relay
    spec.loader.exec_module(relay)
    if (len(relay.TCP_ALLOWLIST_RULES) != 288 or relay.MAX_FLOWS > 128
            or not all(relay.allowed(x) for x in (
                "www.youtube.com", "rr1---sn-gxuo03g-ig3s.googlevideo.com",
                "youtubei.googleapis.com", "i.ytimg.com",
                "www.googleapis.com", "www.google.com"))
            or any(relay.allowed(x) for x in (
                "example.org", "api.telegram.org", "evilgooglevideo.com",
                "googlevideo.com.evil.test", "127.0.0.1"))):
        raise RuntimeError("Existing QUIC allowlist unsafe or drifted")
    # The existing router restricts the DE-private role to the RU WG peer.
    # A distinct 'de-public' role uses its existing public YouTube origin
    # selection while preserving the QUIC SNI allowlist and flow limits.
    return relay

async def serve():
    relay = load_pinned_relay()
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: relay.YoutubeRouter("de-public", "", PUBLIC_IP),
        local_addr=(PUBLIC_IP, PUBLIC_PORT),
    )
    print("DE89_PUBLIC_QUIC_443_LISTENING=true", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()

def main():
    if sys.argv[1:] == ["--self-test"]:
        load_pinned_relay()
        print("DE89_PUBLIC_QUIC_PINNED_ALLOWLIST_AND_PARSER=PASS", flush=True)
    elif len(sys.argv) == 1:
        asyncio.run(serve())
    else:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
