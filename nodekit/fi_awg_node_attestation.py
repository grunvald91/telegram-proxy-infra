#!/usr/bin/env python3
"""RU188 -> FI217 real-key canary proof, deliberately NOT an apply ACK.

A disposable signed grant/revoke bundle is verified by the real FI node
in-memory transition algorithm and against FI's pinned controller SPKI. The FI
node then signs a DIFFERENT test-only domain, which cannot be interpreted as
MNEBYVPN_AWG_APPLIED_V1. No live AWG interface, ledger, billing, grant, outbox,
real receipt, profile or VPN connection is modified.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile

import fi_awg_signed_canary as canary

DOMAIN = "MNEBYVPN_AWG_TEST_PROOF_V1"
NONCE = re.compile(r"[a-f0-9]{64}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")
MAX = 6000
MAX_SKEW_SECONDS = 160
EXPECTED_KEYS = {"schema", "nodeId", "nonce", "issuedAt",
                 "grantSha256", "revokeSha256"}
PROOF_KEYS = EXPECTED_KEYS | {"witnessedAt", "signature"}


def fail(code: str) -> None:
    # Never print an input payload, secret, signature or private key.
    print("FI_AWG_TEST_PROOF_BLOCKED=" + code, file=sys.stderr)
    raise canary.CanaryError(code)


def pairs_unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate_json_key")
        result[key] = value
    return result


def read_json(path: Path, limit: int = MAX) -> dict:
    if path.is_symlink() or not path.is_file():
        fail("missing_test_input")
    st = path.stat()
    if st.st_mode & 0o077 or st.st_size < 2 or st.st_size > limit:
        fail("untrusted_test_input")
    try:
        data = json.loads(path.read_bytes(), object_pairs_hook=pairs_unique)
    except (ValueError, UnicodeDecodeError, TypeError):
        fail("invalid_test_json")
    if not isinstance(data, dict):
        fail("test_input_not_object")
    return data


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def command_hashes(bundle: dict) -> tuple[str, str]:
    if set(bundle) != {"version", "nodeId", "grant", "revoke"} or (
            bundle["version"] != 1 or bundle["nodeId"] != canary.NODE_ID):
        fail("unknown_test_bundle")
    commands = (bundle["grant"], bundle["revoke"])
    if any(not isinstance(command, dict) for command in commands):
        fail("missing_test_commands")
    if commands[0].get("op") != "grant" or commands[1].get("op") != "revoke":
        fail("incorrect_test_command_order")
    return tuple(hashlib.sha256(canonical(command)).hexdigest()
                 for command in commands)


def parse_iso(value: object) -> dt.datetime:
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", value):
        fail("bad_test_timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("bad_test_timestamp")
    if canary.iso(parsed) != value:
        fail("uncanonical_timestamp")
    return parsed


def time_fresh(value: object) -> None:
    current = dt.datetime.now(dt.timezone.utc)
    if abs((current - parse_iso(value)).total_seconds()) > MAX_SKEW_SECONDS:
        fail("test_challenge_expired")


def make_challenge(bundle: dict) -> dict:
    grant, revoke = command_hashes(bundle)
    return {
        "schema": DOMAIN,
        "nodeId": canary.NODE_ID,
        "nonce": secrets.token_hex(32),
        "issuedAt": canary.iso(dt.datetime.now(dt.timezone.utc)),
        "grantSha256": grant, "revokeSha256": revoke,
    }


def check_challenge(challenge: dict, bundle: dict) -> None:
    if (set(challenge) != EXPECTED_KEYS or
            challenge["schema"] != DOMAIN or
            challenge["nodeId"] != canary.NODE_ID or
            not isinstance(challenge["nonce"], str) or
            not NONCE.fullmatch(challenge["nonce"]) or
            (challenge["grantSha256"], challenge["revokeSha256"])
            != command_hashes(bundle)):
        fail("test_challenge_mismatch")
    time_fresh(challenge["issuedAt"])


def test_payload(proof: dict) -> bytes:
    return json.dumps([
        DOMAIN, proof["nodeId"], proof["nonce"], proof["issuedAt"],
        proof["grantSha256"], proof["revokeSha256"], proof["witnessedAt"],
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def node_inactive() -> None:
    if not canary.is_host(canary.FI_IP):
        fail("not_verified_fi_host")
    for name in ("mnebyvpn-nodekit-awg@fi-test-01.service",
                 "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service"):
        cmd = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet",
                              name], capture_output=True, timeout=7)
        if cmd.returncode == 0:
            fail("real_awg_active_test_denied")
    manifest = read_json(canary.FI_NODE / "manifest.json", 10000)
    if (manifest.get("node_id") != canary.NODE_ID or
            manifest.get("advertise_host") != canary.HOST or
            manifest.get("state") != "testing" or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False):
        fail("node_not_isolated_testing")


def respond(bundle_file: Path, challenge_file: Path) -> dict:
    node_inactive()
    bundle = read_json(bundle_file)
    challenge = read_json(challenge_file)
    check_challenge(challenge, bundle)
    # This exercises EXACT production Nodekit in-memory grant/revoke/expiry/
    # replay code and its independently pinned live controller identity.
    canary.node_verify(bundle_file, announce=False)

    priv = canary.FI_NODE / "identity/node-private.pk8"
    pub = canary.FI_NODE / "identity/node-public.spki"
    canonical_pub = canary.pinned_spki(pub, canary.NODE_SHA)
    canary.protected(priv, 256)
    derived = subprocess.run([
        "/usr/bin/openssl", "pkey", "-inform", "DER", "-in", str(priv),
        "-pubout", "-outform", "DER",
    ], capture_output=True, timeout=8, check=False)
    if derived.returncode or derived.stdout != canonical_pub:
        fail("fi_private_key_does_not_match_enrolled_pub")

    proof = {**challenge, "witnessedAt": canary.iso(
        dt.datetime.now(dt.timezone.utc))}
    with tempfile.TemporaryDirectory(prefix="fi-awg-proof-", dir="/run") as folder:
        input_file, output_file = Path(folder) / "payload", Path(folder) / "signature"
        input_file.write_bytes(test_payload(proof))
        input_file.chmod(0o600)
        result = subprocess.run([
            "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(priv),
            "-keyform", "DER", "-rawin", "-in", str(input_file),
            "-out", str(output_file),
        ], capture_output=True, timeout=8, check=False)
        if result.returncode:
            fail("fi_test_proof_signer_failed")
        raw = output_file.read_bytes()
    if len(raw) != 64:
        fail("fi_test_proof_bad_signature")
    proof["signature"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return proof


def verify(bundle_file: Path, challenge_file: Path, proof_file: Path,
           public_file: Path) -> None:
    bundle = read_json(bundle_file)
    challenge = read_json(challenge_file)
    proof = read_json(proof_file)
    check_challenge(challenge, bundle)
    if set(proof) != PROOF_KEYS or any(
            proof.get(k) != v for k, v in challenge.items()):
        fail("fi_test_proof_not_bound")
    time_fresh(proof["witnessedAt"])
    # The runner and FI217 may have a small NTP offset. Signature validity
    # comes from the pinned FI key, fresh unguessable nonce and the 160s
    # issuance/witness TTLs, not strict ordering of two different wall clocks.
    # Still reject a large backwards step instead of masking a broken clock.
    if parse_iso(proof["witnessedAt"]) < parse_iso(challenge["issuedAt"]) - dt.timedelta(seconds=30):
        fail("fi_witness_precedes_challenge")
    sig = proof["signature"]
    if not isinstance(sig, str) or not SIG.fullmatch(sig):
        fail("fi_test_proof_signature_format")
    raw = base64.urlsafe_b64decode(sig + "==")
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != sig:
        fail("fi_test_proof_signature_encoding")
    key = public_file.read_bytes() if public_file.is_file() and (
        not public_file.is_symlink()) else b""
    if (len(key) != 44 or not key.startswith(canary.SPKI_HEADER) or
            hashlib.sha256(key).hexdigest() != canary.NODE_SHA):
        fail("fi_test_proof_untrusted_public_key")
    with tempfile.TemporaryDirectory(prefix="fi-awg-proof-check-") as folder:
        message, signature = Path(folder) / "payload", Path(folder) / "signature"
        message.write_bytes(test_payload(proof))
        signature.write_bytes(raw)
        result = subprocess.run([
            "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
            "-inkey", str(public_file), "-keyform", "DER",
            "-rawin", "-in", str(message), "-sigfile", str(signature),
        ], capture_output=True, timeout=8, check=False)
        if result.returncode:
            fail("fi_test_proof_crypto_rejected")
    print("FI_AWG_REAL_NODE_TEST_PROOF=verified_controller_signed_grant_revoke;"
          "NODE_PRIVATE_KEY_CONFIRMED=true;NODE_APPLIED_RECEIPT=false;"
          "LEDGER_CHANGED=false;CUSTOMER_RELEASE=false")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", required=True, choices=("issue", "respond", "verify"))
    p.add_argument("--signed", type=Path, required=True)
    p.add_argument("--challenge", type=Path)
    p.add_argument("--proof", type=Path)
    p.add_argument("--node-public", type=Path)
    args = p.parse_args()
    if args.mode == "issue":
        if args.challenge or args.proof or args.node_public:
            fail("unexpected_issue_arguments")
        print(json.dumps(make_challenge(read_json(args.signed)),
                         sort_keys=True, separators=(",", ":")))
    elif args.mode == "respond":
        if not args.challenge or args.proof or args.node_public:
            fail("unexpected_fi_arguments")
        print(json.dumps(respond(args.signed, args.challenge),
                         sort_keys=True, separators=(",", ":")))
    else:
        if not args.challenge or not args.proof or not args.node_public:
            fail("missing_test_verification_arguments")
        verify(args.signed, args.challenge, args.proof, args.node_public)


if __name__ == "__main__":
    try:
        main()
    except (canary.CanaryError, OSError, ValueError, TypeError,
            UnicodeError, KeyError, subprocess.SubprocessError,
            subprocess.TimeoutExpired):
        raise SystemExit(2)
