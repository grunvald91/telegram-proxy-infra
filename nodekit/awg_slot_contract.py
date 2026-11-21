"""Pure AWG slot-bound V2 contract; never applies peers or opens connections.

V1 continues to identify grants by entitlement UUID. V2 identifies an
independent peer by (entitlement UUID, slot 1..3), with separate signed domain
and strictly increasing per-slot revision. No live Nodekit mode calls this
module yet: an authenticated per-slot worker+watchdog migration is required.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

import awg_peer_grants as v1

DOMAIN = "MNEBYVPN_AWG_DEVICE_LEASE_V2"
RECEIPT_DOMAIN = "MNEBYVPN_AWG_DEVICE_APPLIED_V2"
COMMAND_FIELDS = {
    "nodeId", "op", "entitlementId", "slotNumber", "revision",
    "peerPublicKey", "clientIpv4", "expiresAt", "issuedAt", "nonce",
    "signature",
}
RECEIPT_FIELDS = {
    "nodeId", "op", "entitlementId", "slotNumber", "revision",
    "commandSha256", "appliedAt", "nonce", "signature",
}
ROW_FIELDS = v1.ROW_FIELDS
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


class SlotError(ValueError):
    pass


def _utc(value: str) -> float:
    try:
        return v1.utc_seconds(value)
    except v1.GrantError as exc:
        raise SlotError("Noncanonical V2 UTC timestamp") from exc


def _key(value: str) -> bool:
    if not v1.valid_key(value):
        return False
    return any(base64.b64decode(value, validate=True))


def _ip(value: str) -> bool:
    return v1.valid_ipv4(value) and not value.endswith(".253")


def _identity(entitlement: str, slot: int) -> str:
    if not v1.valid_uuid(entitlement) or type(slot) is not int or not 1 <= slot <= 3:
        raise SlotError("Unapproved owner slot identity")
    return f"{entitlement}:{slot}"


def signed_message(command: dict) -> bytes:
    return json.dumps([
        DOMAIN, command["nodeId"], command["op"], command["entitlementId"],
        command["slotNumber"], command["revision"], command["peerPublicKey"],
        command["clientIpv4"], command["expiresAt"], command["issuedAt"],
        command["nonce"],
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def receipt_message(receipt: dict) -> bytes:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise SlotError("Invalid V2 receipt envelope")
    return json.dumps([
        RECEIPT_DOMAIN, receipt["nodeId"], receipt["op"],
        receipt["entitlementId"], receipt["slotNumber"], receipt["revision"],
        receipt["commandSha256"], receipt["appliedAt"], receipt["nonce"],
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def validate_command(req: dict, node_id: str, now: float) -> None:
    if (not isinstance(req, dict) or set(req) != COMMAND_FIELDS or
            node_id != "fi-test-01" or req["nodeId"] != node_id or
            req["op"] not in ("grant", "revoke") or
            type(req["slotNumber"]) is not int or
            not 1 <= req["slotNumber"] <= 3 or
            not v1.valid_uuid(req["entitlementId"]) or
            type(req["revision"]) is not int or
            not 1 <= req["revision"] <= 1_000_000_000 or
            not _key(req["peerPublicKey"]) or
            not _ip(req["clientIpv4"]) or
            not isinstance(req["nonce"], str) or
            not HEX64.fullmatch(req["nonce"]) or
            not isinstance(req["signature"], str) or
            not v1.SIGNATURE.fullmatch(req["signature"])):
        raise SlotError("Invalid V2 per-slot AWG command")
    if abs(now - _utc(req["issuedAt"])) > 45:
        raise SlotError("Stale signed V2 command")
    if req["op"] == "grant":
        until = _utc(req["expiresAt"])
        if not now < until <= now + v1.MAX_LEASE_SECONDS:
            raise SlotError("Invalid per-slot lease expiry")
    elif req["expiresAt"] is not None:
        raise SlotError("Revoke must clear per-slot expiry")


def empty_state(node_id: str) -> dict:
    if node_id != "fi-test-01":
        raise SlotError("V2 rollout is FI-only")
    return {"schema_version": 2, "node_id": node_id, "grants": {}}


def validate_state(state: dict, node_id: str) -> dict:
    if (not isinstance(state, dict) or set(state) !=
            {"schema_version", "node_id", "grants"} or
            type(state["schema_version"]) is not int or
            state["schema_version"] != 2 or state["node_id"] != node_id or
            node_id != "fi-test-01" or
            not isinstance(state["grants"], dict) or
            len(state["grants"]) > v1.MAX_PEERS):
        raise SlotError("Invalid V2 peer ledger")
    peers, ips = set(), set()
    for identifier, row in state["grants"].items():
        if not isinstance(identifier, str) or identifier.count(":") != 1:
            raise SlotError("Invalid V2 slot address")
        uid, slot = identifier.split(":")
        if slot not in ("1", "2", "3") or identifier != _identity(uid, int(slot)):
            raise SlotError("Invalid V2 slot identity")
        if (not isinstance(row, dict) or set(row) != ROW_FIELDS or
                type(row["revision"]) is not int or
                not 1 <= row["revision"] <= 1_000_000_000 or
                type(row["enabled"]) is not bool or
                not _key(row["peerPublicKey"]) or
                not _ip(row["clientIpv4"])):
            raise SlotError("Invalid V2 slot row")
        if row["enabled"]:
            _utc(row["expiresAt"])
        elif row["expiresAt"] is not None:
            raise SlotError("V2 revoked slot retains expiry")
        if row["peerPublicKey"] in peers or row["clientIpv4"] in ips:
            raise SlotError("Repeated V2 peer/IP across slots")
        peers.add(row["peerPublicKey"])
        ips.add(row["clientIpv4"])
    return state


def transition(state: dict, command: dict, now: float) -> dict:
    validate_state(state, state["node_id"])
    validate_command(command, state["node_id"], now)
    key = _identity(command["entitlementId"], command["slotNumber"])
    result = copy.deepcopy(state)
    grants = result["grants"]
    old = grants.get(key)
    if old:
        if command["revision"] <= old["revision"]:
            raise SlotError("Stale V2 per-slot revision/replay")
        if (old["peerPublicKey"] != command["peerPublicKey"] or
                old["clientIpv4"] != command["clientIpv4"]):
            raise SlotError("V2 key/address rotation requires separate revocation")
    elif command["op"] == "revoke":
        raise SlotError("Cannot revoke an unknown V2 slot")
    elif len(grants) >= v1.MAX_PEERS:
        raise SlotError("No AWG slot capacity")
    for name, row in grants.items():
        if name != key and (row["peerPublicKey"] == command["peerPublicKey"] or
                            row["clientIpv4"] == command["clientIpv4"]):
            raise SlotError("Duplicate V2 peer or IP across slots")
    grants[key] = {
        "revision": command["revision"],
        "peerPublicKey": command["peerPublicKey"],
        "clientIpv4": command["clientIpv4"],
        "expiresAt": command["expiresAt"] if command["op"] == "grant" else None,
        "enabled": command["op"] == "grant",
    }
    return validate_state(result, state["node_id"])


def merged_active_peers(legacy: dict, slots: dict, now: float) -> list[dict]:
    """Fail closed on duplicate credentials/IPs even across V1 and V2 tombstones."""
    v1.validate_state(legacy, legacy["node_id"])
    validate_state(slots, legacy["node_id"])
    if legacy["node_id"] != slots["node_id"]:
        raise SlotError("Cannot merge different AWG nodes")
    if len(legacy["grants"]) + len(slots["grants"]) > v1.MAX_PEERS:
        raise SlotError("Combined V1/V2 AWG peer capacity exceeded")
    historical_peers = set()
    historical_ips = set()
    for state in (legacy, slots):
        for row in state["grants"].values():
            if row["peerPublicKey"] in historical_peers or row["clientIpv4"] in historical_ips:
                raise SlotError("V1/V2 peer address collision")
            historical_peers.add(row["peerPublicKey"])
            historical_ips.add(row["clientIpv4"])
    peers = v1.active_peers(legacy, now)
    for row in slots["grants"].values():
        if row["enabled"] and _utc(row["expiresAt"]) > now:
            peers.append({"public_key": row["peerPublicKey"],
                          "allowed_ips": row["clientIpv4"] + "/32"})
    return sorted(peers, key=lambda r: r["allowed_ips"])


def command_digest(command: dict) -> str:
    return hashlib.sha256(signed_message(command)).hexdigest()


def verify_signature(command: dict, pinned_public_der: Path,
                     *, runner=subprocess.run) -> None:
    """Verify V2 bytes with an independently enrolled root-only Ed25519 SPKI.

    Caller MUST validate_command first and reauthorize billing/slot before
    applying any transition. V1 signatures do not verify under V2 domain.
    """
    if (not isinstance(command, dict) or set(command) != COMMAND_FIELDS or
            not isinstance(command.get("signature"), str) or
            not v1.SIGNATURE.fullmatch(command["signature"])):
        raise SlotError("Invalid V2 signed command envelope")
    pinned = v1.protected_file(pinned_public_der, max_bytes=100)
    if len(pinned) != 44 or not pinned.startswith(v1.KEY_PREFIX):
        raise SlotError("Expected pinned controller Ed25519 SPKI")
    try:
        raw = base64.urlsafe_b64decode(command["signature"] + "==")
    except (ValueError, base64.binascii.Error) as exc:
        raise SlotError("Invalid V2 signature encoding") from exc
    if (len(raw) != 64 or
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
            != command["signature"]):
        raise SlotError("Noncanonical V2 signature")
    with tempfile.TemporaryDirectory(prefix="nodekit-v2-verify-") as name:
        message = Path(name) / "message"
        signature = Path(name) / "signature"
        message.write_bytes(signed_message(command))
        signature.write_bytes(raw)
        message.chmod(0o600)
        signature.chmod(0o600)
        try:
            runner([
                "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(pinned_public_der), "-keyform", "DER",
                "-rawin", "-in", str(message), "-sigfile", str(signature),
            ], capture_output=True, check=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SlotError("Controller V2 Ed25519 signature rejected") from exc
