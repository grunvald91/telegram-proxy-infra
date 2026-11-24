"""FI query meter adapter for signed RU188 decisions (private transport injected).

No network listener, SSH command, key discovery or service installation.
The transport must be independently authenticated/confidential and bounded.
The current OpenSSL helpers are a correctness baseline, not a load-tested
production signer; no customer traffic is enabled by importing this module.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from typing import Awaitable, Callable
import uuid

from fi_enrollment_ssh import private_file, openssl_sign, openssl_verify

MAX_WIRE = 4096
HEX = re.compile(r"[a-f0-9]{64}\Z")
SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
DENIALS = {"DENY_INVALID", "DENY_NODE", "DENY_REPLAY", "DENY_DISABLED",
           "DENY_UNKNOWN", "DENY_DUPLICATE", "DENY_INACTIVE", "DENY_QUOTA"}


class MeterRpcError(ValueError):
    pass


def canonical(values: list) -> bytes:
    return json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode("utf8")


def request_bytes(request: dict) -> bytes:
    return canonical(["MNEBYVPN_FI_DNS_METER_REQUEST_V1", request["version"],
                      request["nodeId"], request["countryCode"], request["op"],
                      request["requestId"], request["tokenSha256"],
                      request["issuedAt"], request["nonce"]])


def decision_bytes(decision: dict) -> bytes:
    return canonical(["MNEBYVPN_FI_DNS_METER_DECISION_V1", decision["version"],
                      decision["requestSha256"], decision["result"],
                      decision["decidedAt"]])


def timestamp(now: float) -> str:
    return dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def unique_object(pairs: list) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            raise MeterRpcError("Duplicate meter response field")
        out[key] = value
    return out


def validate_decision(raw: bytes, request: dict, now: float) -> tuple[dict, bytes]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_WIRE:
        raise MeterRpcError("Invalid meter response size")
    obj = json.loads(raw.decode("utf8"), object_pairs_hook=unique_object)
    if (not isinstance(obj, dict) or set(obj) != {
        "version", "requestSha256", "result", "decidedAt", "signature"}
        or type(obj["version"]) is not int or obj["version"] != 1
        or obj["requestSha256"] != hashlib.sha256(request_bytes(request)).hexdigest()
        or not isinstance(obj["decidedAt"], str)
        or not UTC.fullmatch(obj["decidedAt"])
        or not isinstance(obj["signature"], str)
        or not SIG.fullmatch(obj["signature"])):
        raise MeterRpcError("Unbound meter response")
    decided = dt.datetime.fromisoformat(obj["decidedAt"].replace("Z", "+00:00")).timestamp()
    if timestamp(decided) != obj["decidedAt"] or abs(now - decided) > 15:
        raise MeterRpcError("Stale meter response")
    result = obj["result"]
    allowed = {"RESERVED"} if request["op"] == "reserve" else {"SETTLED", "RELEASED"}
    if not isinstance(result, str) or result not in allowed | DENIALS:
        raise MeterRpcError("Unexpected meter result")
    signature = base64.urlsafe_b64decode(obj["signature"] + "==")
    if len(signature) != 64 or base64.urlsafe_b64encode(signature).rstrip(b"=").decode() != obj["signature"]:
        raise MeterRpcError("Noncanonical meter signature")
    return obj, signature


class SignedQueryMeter:
    """Implements the metered DoT QueryMeter interface, never trusts plain booleans."""

    def __init__(self, transport: Callable[[bytes], Awaitable[bytes]],
                 node_sign: Callable[[bytes], bytes],
                 controller_verify: Callable[[bytes, bytes], None],
                 *, clock: Callable[[], float] = time.time):
        if not all(callable(x) for x in (transport, node_sign, controller_verify, clock)):
            raise MeterRpcError("Missing required private meter dependencies")
        self.transport, self.node_sign = transport, node_sign
        self.controller_verify, self.clock = controller_verify, clock

    async def _apply(self, op: str, request_id: uuid.UUID, digest: str | None = None) -> str:
        if not isinstance(request_id, uuid.UUID) or request_id.version != 4:
            raise MeterRpcError("Invalid meter request ID")
        if op == "reserve" and (not isinstance(digest, str) or not HEX.fullmatch(digest)):
            raise MeterRpcError("Invalid meter credential digest")
        request = {"version": 1, "nodeId": "fi-test-01", "countryCode": "FI",
                   "op": op, "requestId": str(request_id), "tokenSha256": digest,
                   "issuedAt": timestamp(self.clock()), "nonce": secrets.token_hex(32)}
        signature = await asyncio.to_thread(self.node_sign, request_bytes(request))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise MeterRpcError("Invalid node signer result")
        raw = await self.transport(json.dumps({**request, "signature":
            base64.urlsafe_b64encode(signature).rstrip(b"=").decode()},
            separators=(",", ":")).encode())
        decision, proof = validate_decision(raw, request, self.clock())
        await asyncio.to_thread(self.controller_verify, decision_bytes(decision), proof)
        # Check again after the potentially slow verification.
        validate_decision(raw, request, self.clock())
        return decision["result"]

    async def reserve(self, token_sha256: str, request_id: uuid.UUID) -> bool:
        return await self._apply("reserve", request_id, token_sha256) == "RESERVED"

    async def settle(self, request_id: uuid.UUID) -> bool:
        return await self._apply("settle", request_id) == "SETTLED"

    async def release(self, request_id: uuid.UUID) -> None:
        if await self._apply("release", request_id) not in ("RELEASED", "SETTLED"):
            raise MeterRpcError("Meter cleanup not confirmed")


def protected_openssl_meter(transport: Callable[[bytes], Awaitable[bytes]],
                           node_private_der: Path, controller_public_der: Path,
                           controller_pin: str) -> SignedQueryMeter:
    """Root-only existing enrollment keys; independent controller SPKI pin."""
    private_file(node_private_der)
    def verify_controller(message: bytes, signature: bytes) -> None:
        raw = private_file(controller_public_der, 100)
        if (not isinstance(controller_pin, str) or not HEX.fullmatch(controller_pin)
            or len(raw) != 44 or not raw.startswith(bytes.fromhex("302a300506032b6570032100"))
            or hashlib.sha256(raw).hexdigest() != controller_pin):
            raise MeterRpcError("Untrusted meter controller key")
        openssl_verify(controller_public_der, signature, message)
    def sign_node(message: bytes) -> bytes:
        private_file(node_private_der)
        return openssl_sign(node_private_der, message)
    return SignedQueryMeter(transport, sign_node, verify_controller)
