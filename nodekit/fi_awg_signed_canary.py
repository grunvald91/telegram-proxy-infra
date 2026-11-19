#!/usr/bin/env python3
"""FI217 signed AWG grant/revoke protocol canary. NO live peer application.

Run --mode issue ONLY on RU188: sign disposable 120-second grant and
revision-2 revoke using RU188's existing pinned root-only controller signer.
Run --mode verify ONLY on FI217: verify both signatures and the actual
Nodekit in-memory transitions, expiry, and replay rejection.
No PostgreSQL, production AWG interface, watchdog, peer ledger, client keys,
subscriptions, firewall or routing is modified. Never log signed commands.
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

RU_IP = "188.120.254.223"
FI_IP = "217.11.167.91"
NODE_ID = "fi-test-01"
HOST = "fi.mnebyvpn.site"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
RU_ROOT = Path("/root/mnebyvpn-controller")
FI_NODE = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
SPKI_HEADER = bytes.fromhex("302a300506032b6570032100")
EXPIRY_SECONDS = 120
# An arbitrary 32-byte value with NO associated private key is used. This
# synthetic "peer" cannot successfully authenticate an AWG handshake.
IP = "10.73.91.254"


class CanaryError(Exception):
    pass


def stop(reason: str) -> None:
    print("FI_AWG_SIGNED_CANARY_BLOCKED=" + reason, file=sys.stderr)
    raise CanaryError(reason)


def is_host(ip: str) -> bool:
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        if len(name.encode()) > 15:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                data = fcntl.ioctl(sock.fileno(), 0x8915,
                                   struct.pack("256s", name.encode()))
                if socket.inet_ntoa(data[20:24]) == ip:
                    return True
            except OSError:
                pass
    return False


def protected(path: Path, max_bytes: int = 8192) -> bytes:
    for directory in path.parents:
        try:
            info = directory.lstat()
        except OSError:
            stop("protected_parent_absent")
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022):
            stop("untrusted_protected_parent")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        stop("protected_asset_absent")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o077 or info.st_nlink != 1 or
                not 1 <= info.st_size <= max_bytes):
            stop("untrusted_protected_asset")
        data = os.read(fd, max_bytes + 1)
        if len(data) != info.st_size:
            stop("protected_asset_changed")
        return data
    finally:
        os.close(fd)


def pinned_spki(path: Path, digest: str) -> bytes:
    data = protected(path, 100)
    if (len(data) != 44 or not data.startswith(SPKI_HEADER) or
            hashlib.sha256(data).hexdigest() != digest):
        stop("pinned_controller_or_node_identity_mismatch")
    return data


def iso(timestamp: dt.datetime) -> str:
    return timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def message(command: dict) -> bytes:
    return json.dumps([
        "MNEBYVPN_AWG_LEASE_V1", command["nodeId"], command["op"],
        command["entitlementId"], command["revision"],
        command["peerPublicKey"], command["clientIpv4"],
        command["expiresAt"], command["issuedAt"], command["nonce"],
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def sign(key: Path, command: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="fi-awg-sign-",
                                          dir="/run" if os.geteuid() == 0 else None) as temporary:
        data = Path(temporary) / "message"
        data.write_bytes(message(command))
        data.chmod(0o600)
        try:
            result = subprocess.run(
                ["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                 str(key), "-rawin", "-in", str(data)],
                capture_output=True, check=False, timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired):
            stop("controller_signer_unavailable")
        if result.returncode or len(result.stdout) != 64:
            stop("controller_signer_failed")
    return dict(command, signature=base64.urlsafe_b64encode(
        result.stdout).rstrip(b"=").decode("ascii"))


def issue() -> None:
    if not is_host(RU_IP):
        stop("not_existing_ru188")
    expected = pinned_spki(RU_ROOT / "controller-public.spki", CONTROLLER_SHA)
    signer = RU_ROOT / "controller-signing-key.pem"
    protected(signer)
    # Verify that the EXISTING private signer matches its independently pinned
    # public key. Never send the private key to the runner or the node.
    try:
        result = subprocess.run(
            ["/usr/bin/openssl", "pkey", "-in", str(signer),
             "-pubout", "-outform", "DER"],
            capture_output=True, check=False, timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        stop("controller_public_key_derivation_unavailable")
    if result.returncode or result.stdout != expected:
        stop("controller_signer_does_not_match_pinned_key")
    pinned_spki(RU_ROOT / "fi-node-public.spki", NODE_SHA)
    issued = dt.datetime.now(dt.timezone.utc)
    expires = issued + dt.timedelta(seconds=EXPIRY_SECONDS)
    entitlement_id = str(uuid.uuid4())
    # This random byte string is treated as a public key only by the protocol;
    # no corresponding private key is generated, saved or distributed.
    synthetic_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    common = {
        "nodeId": NODE_ID, "entitlementId": entitlement_id,
        "peerPublicKey": synthetic_key, "clientIpv4": IP,
        "issuedAt": iso(issued),
    }
    grant = sign(signer, dict(common, op="grant", revision=1,
                              expiresAt=iso(expires), nonce=secrets.token_hex(32)))
    revoke = sign(signer, dict(common, op="revoke", revision=2,
                               expiresAt=None, nonce=secrets.token_hex(32)))
    bundle = {"version": 1, "nodeId": NODE_ID, "grant": grant, "revoke": revoke}
    # stdout is PRIVATE workflow temp storage, never GitHub Actions logs.
    sys.stdout.write(json.dumps(bundle, separators=(",", ":")) + "\n")


def node_verify(bundle_file: Path) -> None:
    if not is_host(FI_IP):
        stop("not_existing_fi217")
    pinned_spki(FI_NODE / "controller-access.spki", CONTROLLER_SHA)
    pinned_spki(FI_NODE / "identity/node-public.spki", NODE_SHA)
    manifest = json.loads(protected(FI_NODE / "manifest.json", 10000))
    if (manifest.get("node_id") != NODE_ID or
            manifest.get("advertise_host") != HOST or
            manifest.get("state") != "testing" or
            manifest.get("registration_enabled") is not False or
            manifest.get("activation_enabled") is not False):
        stop("fi_is_not_unpublished_testing_node")
    bundle = json.loads(protected(bundle_file, 6000))
    if (not isinstance(bundle, dict) or set(bundle) !=
            {"version", "nodeId", "grant", "revoke"} or
            bundle["version"] != 1 or bundle["nodeId"] != NODE_ID):
        stop("invalid_nonpublishing_canary_bundle")
    # The real node-side verifier and local state machine are tested. Importing
    # this module does not invoke --mode apply or any AWG network change.
    from awg_peer_grants import (
        active_peers, empty_state, transition, validate_command,
        verify_signature, GrantError, utc_seconds,
    )
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    grant, revoke = bundle["grant"], bundle["revoke"]
    for command in (grant, revoke):
        validate_command(command, NODE_ID, now)
        verify_signature(command, FI_NODE / "controller-access.spki")
    if (grant["op"] != "grant" or grant["revision"] != 1 or
            revoke["op"] != "revoke" or revoke["revision"] != 2 or
            grant["entitlementId"] != revoke["entitlementId"] or
            grant["peerPublicKey"] != revoke["peerPublicKey"] or
            grant["clientIpv4"] != revoke["clientIpv4"] or
            grant["clientIpv4"] != IP or
            grant["issuedAt"] != revoke["issuedAt"] or
            utc_seconds(grant["expiresAt"]) - utc_seconds(grant["issuedAt"]) != EXPIRY_SECONDS):
        stop("untrusted_canary_protocol_identity")
    fresh = empty_state(NODE_ID)
    active = transition(fresh, grant, now)
    if len(active_peers(active, now)) != 1 or len(fresh["grants"]) != 0:
        stop("signed_grant_local_authorization_failed")
    if active_peers(active, utc_seconds(grant["expiresAt"]) + 1):
        stop("offline_expired_grant_kept_access")
    revoked = transition(active, revoke, now)
    if active_peers(revoked, now) or revoked["grants"][grant["entitlementId"]]["revision"] != 2:
        stop("signed_revocation_did_not_disable_peer")
    try:
        transition(revoked, grant, now)
    except GrantError:
        pass
    else:
        stop("old_signed_grant_replay_reactivated_peer")
    print("FI_AWG_SIGNED_CANARY=grant_revoke_expiry_replay_verified;"
          "REAL_PEERS_MODIFIED=false;ENTITLEMENTS_MODIFIED=false;"
          "SUBSCRIPTIONS_PUBLISHED=false")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("issue", "verify"), required=True)
    parser.add_argument("--signed", type=Path)
    args = parser.parse_args()
    if args.mode == "issue":
        if args.signed is not None:
            stop("unexpected_canary_input")
        issue()
    else:
        if args.signed is None:
            stop("missing_signed_canary_input")
        node_verify(args.signed)


if __name__ == "__main__":
    try:
        main()
    except (CanaryError, OSError, ValueError, TypeError, UnicodeError,
            subprocess.SubprocessError, KeyError, AttributeError):
        raise SystemExit(2)
