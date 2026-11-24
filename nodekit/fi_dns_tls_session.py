#!/usr/bin/env python3
"""Unpublished FI217 loopback TLS front-end for per-message DNS metering.

This does not include a quota backend or a production entry point. It cannot
operate without explicitly provided signed-grant authorizer AND transactional
quota meter. Unlike the historical passthrough ingress, it terminates local
TLS to inspect each individual DNS question. No public 853 listener, systemd
unit or customer provisioning is created by importing this module.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from pathlib import Path
import ssl
import threading
import weakref

from fi_dns_metered_dot import (
    Authorizer, QueryMeter, Resolver, serve_one_tls_stream,
)
from fi_dns_signed_grants import hostname_digest, authorized
from fi_dns_guarded_ingress import Guard
from fi_regional_cert_stage import DEST as REGIONAL_CERT_DIR, verify_pair

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18854
GLOBAL_CONNECTIONS = 48
PER_CREDENTIAL_CONNECTIONS = 4
PER_HANDSHAKE_TIMEOUT_SEC = 5.0


class SignedFiGrantAuthorizer:
    """Use the current verified RU188 Ed25519 grants; no token databases on FI.

    Verification is offloaded from the event loop and serialized so the
    high-water rollback fence cannot race across concurrent DNS questions.
    """

    def __init__(self, expected_controller_sha: str):
        self.guard = Guard(expected_controller_sha)
        self._lock = asyncio.Lock()
        self._worker_lock = threading.Lock()

    def _verify_serialized(self) -> dict:
        # Cancelling to_thread does not stop its running worker. Keep the
        # high-water/cache lock inside the worker until verification finishes.
        with self._worker_lock:
            return self.guard._verified_policy()

    async def allowed(self, hostname: str) -> bool:
        try:
            hostname_digest(hostname)
            async with self._lock:
                snapshot = await asyncio.to_thread(self._verify_serialized)
            allowed, _ = authorized(snapshot, hostname)
            return bool(allowed)
        except (OSError, ValueError, TypeError, KeyError):
            return False


class SniBindings:
    """Only true TLS ClientHello SNI controls credential selection."""

    def __init__(self, cert: Path, key: Path):
        self.names: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(cert), str(key))
        self.context.set_servername_callback(self.on_sni)

    def on_sni(self, obj: ssl.SSLObject, name: str | None, _ctx: ssl.SSLContext):
        try:
            hostname_digest(name)
            self.names[obj] = name
            return None
        except (TypeError, ValueError):
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    def from_writer(self, writer: asyncio.StreamWriter) -> str | None:
        tls_object = writer.get_extra_info("ssl_object")
        return self.names.get(tls_object)


async def make_metered_loopback_server(
    *,
    authorizer: Authorizer | None,
    meter: QueryMeter | None,
    resolver: Resolver | None,
    listen_port: int = LISTEN_PORT,
) -> asyncio.AbstractServer:
    """Bind loopback only after certificate and all accounting gates verified.

    A live application must provide its own *atomic durable* RU188 quota
    adapter: no permissive mock, missing meter or plaintext fallback is built
    into this module. Deployment requires a separate reviewed release gate.
    """
    if authorizer is None or meter is None or resolver is None:
        raise ValueError("FI DNS meter, signed authorizer and resolver required")
    if not isinstance(listen_port, int) or not (listen_port == 0 or 1024 <= listen_port <= 65535):
        raise ValueError("Invalid private FI DoT listener port")
    verify_pair(REGIONAL_CERT_DIR)
    binding = SniBindings(
        REGIONAL_CERT_DIR / "fullchain.pem",
        REGIONAL_CERT_DIR / "privkey.pem",
    )
    active = 0
    per_credential: Counter[str] = Counter()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        nonlocal active
        active += 1
        digest: str | None = None
        counted = False
        try:
            # SNI always comes from the actual TLS ClientHello; this mapping
            # is NOT user-supplied metadata. Count each credential in addition
            # to the global maximum, without leaking its bearer hostname.
            name = binding.from_writer(writer)
            if name is None or active > GLOBAL_CONNECTIONS:
                return
            digest = hostname_digest(name)
            if per_credential[digest] >= PER_CREDENTIAL_CONNECTIONS:
                return
            per_credential[digest] += 1
            counted = True
            await serve_one_tls_stream(
                reader, writer, name, authorizer=authorizer,
                meter=meter, resolver=resolver,
            )
        finally:
            if counted and digest is not None:
                per_credential[digest] -= 1
                if per_credential[digest] == 0:
                    del per_credential[digest]
            active -= 1
            if not writer.is_closing():
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2)
                except (OSError, asyncio.TimeoutError, ssl.SSLError):
                    pass

    return await asyncio.start_server(
        handle, host=LISTEN_HOST, port=listen_port,
        ssl=binding.context, ssl_handshake_timeout=PER_HANDSHAKE_TIMEOUT_SEC,
        backlog=GLOBAL_CONNECTIONS,
    )
