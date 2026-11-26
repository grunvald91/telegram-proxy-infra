#!/usr/bin/env python3
"""FI217 *dormant* per-DNS-message metering core for country-bound DoT.

This module has NO main(), public listener, hard-coded entitlement, bypass
meter, or automatic service installation. The current FI ingress is TLS
passthrough and cannot count DNS questions. A future TLS-terminating gateway
must obtain the actual SNI from its verified TLS handshake, validate a fresh
RU188 signed grant on EVERY question, and bind a transactional RU188/leased
quota provider before serving any customer. This library implements the
frame/accounting boundary; production release is NOT implied.
"""
from __future__ import annotations

import asyncio
import ssl
import struct
from collections.abc import Callable
from typing import Protocol
import uuid

from fi_dns_signed_grants import hostname_digest

MAX_DNS_BYTES = 16_384
MAX_QUESTIONS_PER_SOCKET = 10_000
IDLE_TIMEOUT_SECONDS = 30.0
UPSTREAM_TIMEOUT_SECONDS = 8.0
METER_TIMEOUT_SECONDS = 3.0
RELEASE_TIMEOUT_SECONDS = 3.0
WRITE_TIMEOUT_SECONDS = 3.0


class MeteredDnsError(ValueError):
    """Fail closed. Never include a hostname, token, query or SQL in the text."""


class Authorizer(Protocol):
    async def allowed(self, hostname: str) -> bool:
        """Verify a fresh FI signed grant, its revocation and expiry."""


class QueryMeter(Protocol):
    async def reserve(self, token_sha256: str, request_id: uuid.UUID) -> bool:
        """Atomically reserve one DNS question against an approved entitlement."""

    async def settle(self, request_id: uuid.UUID) -> bool:
        """Atomically charge one reserved answered question; idempotent."""

    async def release(self, request_id: uuid.UUID) -> None:
        """Idempotently release or tombstone this request, including unknown IDs.

        A late reserve must not resurrect a released ID; a settled charge
        must never be undone. The durable backend must expire orphan holds.
        """


class Resolver(Protocol):
    async def resolve(self, query: bytes) -> bytes:
        """Return one complete DNS response, never a TCP length prefix."""


def question_end(packet: bytes) -> int:
    """Validate one standard DNS question and return end of question section.

    Compression pointers in the question are rejected to avoid ambiguous
    names. Replies may use compression *after* this question.
    """
    if not isinstance(packet, bytes) or not 17 <= len(packet) <= MAX_DNS_BYTES:
        raise MeteredDnsError("Invalid DNS frame size")
    _, flags, qd, answers, authority, extra = struct.unpack("!HHHHHH", packet[:12])
    if (flags & 0x8000 or (flags >> 11) & 0xF or flags & 0x0200 or
            qd != 1 or answers != 0 or authority != 0 or extra > 2):
        raise MeteredDnsError("Unsupported DNS question header")
    p = 12
    total = 1
    while True:
        if p >= len(packet):
            raise MeteredDnsError("Incomplete DNS question")
        size = packet[p]
        p += 1
        if size == 0:
            break
        if size > 63 or p + size > len(packet):
            raise MeteredDnsError("Invalid DNS QNAME")
        total += size + 1
        if total > 255:
            raise MeteredDnsError("DNS QNAME too long")
        p += size
    if total <= 1 or p + 4 > len(packet):
        raise MeteredDnsError("Empty or incomplete DNS question")
    kind, qclass = struct.unpack("!HH", packet[p:p+4])
    if kind in (0, 251, 252, 255) or qclass not in (1,):
        raise MeteredDnsError("Unsupported DNS query type or class")
    end = p + 4
    _validate_records(packet, end, extra)
    return end


def _name_end(packet: bytes, start: int) -> int:
    """Validate an RR owner name, including bounded backwards compression."""
    p = start
    consumed = None
    expanded = 1
    visited = set()
    while True:
        if p >= len(packet) or p in visited:
            raise MeteredDnsError("Invalid DNS record name")
        visited.add(p)
        size = packet[p]
        if size == 0:
            return p + 1 if consumed is None else consumed
        if size & 0xC0 == 0xC0:
            if p + 1 >= len(packet):
                raise MeteredDnsError("Incomplete DNS compression pointer")
            target = ((size & 0x3F) << 8) | packet[p + 1]
            if not 12 <= target < p:
                raise MeteredDnsError("Invalid DNS compression pointer")
            if consumed is None:
                consumed = p + 2
            p = target
            continue
        if size > 63 or p + 1 + size > len(packet):
            raise MeteredDnsError("Invalid DNS record label")
        expanded += 1 + size
        if expanded > 255:
            raise MeteredDnsError("DNS record name too long")
        p += 1 + size


def _validate_records(packet: bytes, offset: int, count: int) -> None:
    """Check RR envelopes and exact packet length; RDATA remains opaque."""
    for _ in range(count):
        offset = _name_end(packet, offset)
        if offset + 10 > len(packet):
            raise MeteredDnsError("Incomplete DNS record header")
        rdlength = int.from_bytes(packet[offset + 8:offset + 10], "big")
        offset += 10 + rdlength
        if offset > len(packet):
            raise MeteredDnsError("Incomplete DNS record data")
    if offset != len(packet):
        raise MeteredDnsError("Unexpected trailing DNS bytes")


def valid_answer(query: bytes, response: bytes) -> None:
    qend = question_end(query)
    if not isinstance(response, bytes) or not 17 <= len(response) <= MAX_DNS_BYTES:
        raise MeteredDnsError("Invalid DNS answer length")
    ident, flags, questions, answers, authority, extra = struct.unpack("!HHHHHH", response[:12])
    if (ident != int.from_bytes(query[:2], "big") or
            not flags & 0x8000 or (flags >> 11) & 0xF or
            flags & 0x0200 or questions != 1 or
            len(response) < qend or response[12:qend] != query[12:qend]):
        raise MeteredDnsError("Unrelated or malformed DNS answer")
    _validate_records(response, qend, answers + authority + extra)
    # NXDOMAIN and SERVFAIL are valid DNS replies, but quota settlement still
    # requires a complete response. We do not fabricate answers locally.


async def charge_one_question(
    hostname: str, query: bytes, *,
    authorizer: Authorizer | None, meter: QueryMeter | None,
    resolver: Resolver | None,
    chargeable: Callable[[bytes], bool] | None = None,
) -> bytes:
    """Refuse unauthorized/over-quota queries BEFORE opening any upstream.

    Reservation must be atomic for the entitlement shared between connections
    (and other regions where applicable). Only an explicit positive settlement
    allows the DNS response to be sent. No permissive default.
    """
    question_end(query)
    if authorizer is None or meter is None or resolver is None:
        raise MeteredDnsError("Missing required query authorization or meter")
    try:
        token_sha256 = hostname_digest(hostname)
    except ValueError as exc:
        raise MeteredDnsError("Unsupported FI DNS hostname") from exc
    if await asyncio.wait_for(
        authorizer.allowed(hostname), timeout=METER_TIMEOUT_SECONDS
    ) is not True:
        raise MeteredDnsError("Inactive or revoked FI entitlement")

    async def still_allowed():
        if await asyncio.wait_for(authorizer.allowed(hostname), timeout=METER_TIMEOUT_SECONDS) is not True:
            raise MeteredDnsError("FI DNS grant revoked while resolving")

    if chargeable is not None and not chargeable(query):
        result = await asyncio.wait_for(resolver.resolve(query), timeout=UPSTREAM_TIMEOUT_SECONDS)
        valid_answer(query, result)
        await still_allowed()
        return result

    request_id = uuid.uuid4()
    attempted = False
    settled = False
    try:
        # A timeout is ambiguous: the controller may already have committed.
        attempted = True
        if await asyncio.wait_for(
            meter.reserve(token_sha256, request_id),
            timeout=METER_TIMEOUT_SECONDS,
        ) is not True:
            if chargeable is not None:
                flags = 0x8082 | (query[2] & 1) << 8
                return query[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + query[12:question_end(query)]
            raise MeteredDnsError("FI DNS quota denied")
        result = await asyncio.wait_for(
            resolver.resolve(query), timeout=UPSTREAM_TIMEOUT_SECONDS
        )
        valid_answer(query, result)
        if chargeable is not None:
            await still_allowed()
        settled = (await asyncio.wait_for(
            meter.settle(request_id), timeout=METER_TIMEOUT_SECONDS
        )) is True
        if not settled:
            raise MeteredDnsError("DNS settlement not confirmed")
        if chargeable is not None:
            await still_allowed()
        return result
    finally:
        if attempted and not settled:
            # Even a denied or timed-out reserve needs an idempotent cleanup.
            # The backend must fence late reserves and expire orphan holds;
            # cleanup must not indefinitely occupy a client stream.
            try:
                await asyncio.wait_for(
                    meter.release(request_id), timeout=RELEASE_TIMEOUT_SECONDS
                )
            except Exception:
                pass


async def serve_one_tls_stream(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    hostname: str, *, authorizer: Authorizer | None,
    meter: QueryMeter | None, resolver: Resolver | None,
    chargeable: Callable[[bytes], bool] | None = None,
) -> None:
    """Sequential RFC7858 two-byte framed questions on an authenticated TLS stream.

    Only pass hostname captured from the TLS SNI handshake, NOT untrusted HTTP
    headers or a DNS QNAME. No pipelining or customer data logging.
    """
    try:
        # Revalidate separately for each question so a revocation/expiry
        # becomes effective even on a long-lived Android Private DNS socket.
        for _ in range(MAX_QUESTIONS_PER_SOCKET):
            length = await asyncio.wait_for(
                reader.readexactly(2), timeout=IDLE_TIMEOUT_SECONDS
            )
            size = struct.unpack("!H", length)[0]
            if not 17 <= size <= MAX_DNS_BYTES:
                raise MeteredDnsError("Unsafe DNS frame")
            request = await asyncio.wait_for(
                reader.readexactly(size), timeout=IDLE_TIMEOUT_SECONDS
            )
            answer = await charge_one_question(
                hostname, request, authorizer=authorizer,
                meter=meter, resolver=resolver, chargeable=chargeable,
            )
            writer.write(struct.pack("!H", len(answer)) + answer)
            await asyncio.wait_for(writer.drain(), timeout=WRITE_TIMEOUT_SECONDS)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError,
            ValueError, ssl.SSLError):
        # Fail closed. The next query must reconnect and reauthorize.
        pass
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            pass


class LoopbackTlsResolver:
    """Verified FI CoreDNS origin; never routes plaintext outside localhost."""

    def __init__(self, tls_hostname: str, port: int = 8853):
        # Same regional certificate as the client; require genuine FI SAN.
        hostname_digest(tls_hostname)
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise MeteredDnsError("Unapproved origin port")
        self.hostname = tls_hostname
        self.port = port

    async def resolve(self, query: bytes) -> bytes:
        question_end(query)
        context = ssl.create_default_context()
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", self.port,
                    ssl=context, server_hostname=self.hostname,
                ),
                timeout=3,
            )
            writer.write(struct.pack("!H", len(query)) + query)
            await asyncio.wait_for(writer.drain(), timeout=3)
            wire = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            length = struct.unpack("!H", wire)[0]
            if not 17 <= length <= MAX_DNS_BYTES:
                raise MeteredDnsError("Invalid FI origin DNS frame")
            response = await asyncio.wait_for(
                reader.readexactly(length), timeout=5
            )
            valid_answer(query, response)
            return response
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2)
                except (OSError, asyncio.TimeoutError, ssl.SSLError):
                    pass
