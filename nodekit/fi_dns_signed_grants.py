#!/usr/bin/env python3
"""FI217 country-bound personal DoT admission (signed controller snapshots).

Dormant library. No socket, service, DNS rule, certificate, payment or customer
is changed by importing / using it. Each authorized hostname is a transferable
bearer; it is not device identity. RU188 MUST independently verify entitlements
and generate a fresh snapshot every <=60s before any real ingress is enabled.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from awg_peer_grants import protected_file

NODE = "fi-test-01"
COUNTRY = "FI"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
TOKEN_HOST = re.compile(r"([a-z0-9]{12})\.fi\.dns\.mnebyvpn\.site\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
ENVELOPE_KEYS = frozenset((
    "schemaVersion", "nodeId", "countryCode", "revision", "issuedAt",
    "validUntil", "grants", "signature"))
GRANT_KEYS = frozenset((
    "entitlementId", "credentialRevision", "tokenSha256", "expiresAt",
    "state"))
MAX_GRANTS = 2048
MAX_SNAPSHOT_SECONDS = 120
FUTURE_CLOCK_TOLERANCE_SECONDS = 15


class RegionalDnsGrantError(ValueError):
    pass


def fail() -> None:
    raise RegionalDnsGrantError("Untrusted or expired FI regional DNS snapshot")


def utc_seconds(value: object) -> float:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        fail()
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail()
    if stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        fail()
    return stamp.timestamp()


def uuid_ok(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def hostname_digest(hostname: str) -> str:
    """Hash EXACTLY like regional-personal-dot-identity.ts on RU188."""
    if not isinstance(hostname, str):
        fail()
    match = TOKEN_HOST.fullmatch(hostname)
    if not match:
        fail()
    return hashlib.sha256(
        b"MNEBYVPN_COUNTRY_DNS_V1\x00FI\x00" + match[1].encode("ascii")
    ).hexdigest()


def message(data: dict) -> bytes:
    """Canonical v1 Ed25519 signing transcript; interoperable with Node JSON."""
    rows = [[x["entitlementId"], x["credentialRevision"],
             x["tokenSha256"], x["expiresAt"], x["state"]]
            for x in data["grants"]]
    return json.dumps([
        "MNEBYVPN_REGIONAL_DNS_SNAPSHOT_V1",
        data["nodeId"], data["countryCode"], data["revision"],
        data["issuedAt"], data["validUntil"], rows,
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def validate(data: object, now: float) -> dict:
    if (not isinstance(data, dict) or set(data) != ENVELOPE_KEYS or
            type(data["schemaVersion"]) is not int or
            data["schemaVersion"] != 1 or data["nodeId"] != NODE or
            data["countryCode"] != COUNTRY or
            type(data["revision"]) is not int or
            not 1 <= data["revision"] <= 1_000_000_000 or
            not isinstance(data["grants"], list) or
            len(data["grants"]) > MAX_GRANTS or
            not isinstance(data["signature"], str) or
            not SIGNATURE.fullmatch(data["signature"])):
        fail()
    issued = utc_seconds(data["issuedAt"])
    valid_until = utc_seconds(data["validUntil"])
    if (not issued - MAX_SNAPSHOT_SECONDS <= now <= issued +
            FUTURE_CLOCK_TOLERANCE_SECONDS or
            not issued < valid_until <= issued + MAX_SNAPSHOT_SECONDS or
            valid_until <= now):
        fail()
    previous = ""
    seen_entitlements = set()
    for grant in data["grants"]:
        if (not isinstance(grant, dict) or set(grant) != GRANT_KEYS or
                not uuid_ok(grant["entitlementId"]) or
                type(grant["credentialRevision"]) is not int or
                not 1 <= grant["credentialRevision"] <= 1_000_000_000 or
                not isinstance(grant["tokenSha256"], str) or
                not SHA.fullmatch(grant["tokenSha256"]) or
                grant["tokenSha256"] <= previous or
                grant["entitlementId"] in seen_entitlements or
                grant["state"] not in ("ACTIVE", "REVOKED")):
            fail()
        expires = utc_seconds(grant["expiresAt"])
        if expires > issued + 366 * 86400:
            fail()
        previous = grant["tokenSha256"]
        seen_entitlements.add(grant["entitlementId"])
    return data


def verify_signature(data: dict, controller_public_spki: Path,
                     expected_sha256: str, *, runner=subprocess.run) -> None:
    if not isinstance(expected_sha256, str) or not SHA.fullmatch(expected_sha256):
        fail()
    der = protected_file(controller_public_spki, max_bytes=100)
    if (len(der) != 44 or not der.startswith(SPKI_PREFIX) or
            hashlib.sha256(der).hexdigest() != expected_sha256):
        fail()
    signature = data["signature"]
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, base64.binascii.Error):
        fail()
    if (len(raw) != 64 or
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != signature):
        fail()
    with tempfile.TemporaryDirectory(prefix="mnebyvpn-fi-dot-signature-") as tmp:
        t = Path(tmp)
        payload = t / "payload"
        sig = t / "sig"
        payload.write_bytes(message(data))
        sig.write_bytes(raw)
        payload.chmod(0o600)
        sig.chmod(0o600)
        try:
            runner([
                "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(controller_public_spki), "-keyform", "DER",
                "-rawin", "-in", str(payload), "-sigfile", str(sig)
            ], check=True, capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            fail()


def load(snapshot_path: Path, controller_public_spki: Path,
         expected_sha256: str, *, now: float | None = None) -> dict:
    """Read-only, root-owned signed policy loader. NEVER accept unsigned files."""
    raw = protected_file(snapshot_path, max_bytes=350_000)
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        fail()
    valid = validate(data, time.time() if now is None else now)
    verify_signature(valid, controller_public_spki, expected_sha256)
    return valid


def authorized(snapshot: dict, hostname: str, *,
               now: float | None = None) -> tuple[bool, float]:
    """Return access and expiry; caller MUST stop an active stream at expiry.

    This is bounded connection authorization only, NOT DNS query quotas or
    payment settlement. A production data plane must add per-query metering.
    """
    current = time.time() if now is None else now
    try:
        digest = hostname_digest(hostname)
        valid_until = utc_seconds(snapshot["validUntil"])
        if current >= valid_until:
            return False, 0.0
        grants = snapshot["grants"]
        # <=2048 sorted rows; a linear lookup is bounded and easy to audit.
        for grant in grants:
            if grant["tokenSha256"] == digest:
                end = min(valid_until, utc_seconds(grant["expiresAt"]))
                return grant["state"] == "ACTIVE" and end > current, end
    except (TypeError, ValueError, KeyError):
        return False, 0.0
    return False, 0.0
