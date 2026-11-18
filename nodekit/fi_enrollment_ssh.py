#!/usr/bin/env python3
"""FI-only Ed25519 enrollment signer for an OpenSSH forced command.

Reads ONE controller-signed one-time challenge from stdin and writes ONE node
proof to stdout. The node's private key never leaves its own root-only stage.
No listener/service, publish operation, or entitlement access is implemented.
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
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/var/lib/mnebyvpn-nodekit")
NODE = "fi-test-01"
HOST = "fi.mnebyvpn.site"
SHA = re.compile(r"[a-f0-9]{64}\Z")
UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\Z")
B64_43 = re.compile(r"[A-Za-z0-9_-]{43}\Z")
B64_59 = re.compile(r"[A-Za-z0-9_-]{59}\Z")
B64_86 = re.compile(r"[A-Za-z0-9_-]{86}\Z")
FIELDS = {"nodeId","endpointHost","publicSpki","challengeId",
          "nonce","expiresAt","controllerSignature"}
SPKI_HEADER = bytes.fromhex("302a300506032b6570032100")


class EnrollmentSshError(ValueError):
    pass


def private_dir(path: Path) -> None:
    # lstat once: do not follow a symlink into a writable directory.
    try:
        st=path.lstat()
    except OSError as exc:
        raise EnrollmentSshError("Missing protected enrollment directory") from exc
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o077:
        raise EnrollmentSshError("Unsafe enrollment directory")


def private_file(path: Path, max_bytes: int = 4096) -> bytes:
    # Open without following links, then validate the SAME inode we read.
    # O_NONBLOCK prevents an unexpected FIFO/device from hanging root SSH.
    if not isinstance(max_bytes,int) or not 1<=max_bytes<=10000:
        raise EnrollmentSshError("Unbounded enrollment file")
    try:
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    except OSError as exc:
        raise EnrollmentSshError("Missing or linked enrollment file") from exc
    try:
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or
                st.st_mode & 0o077 or not 1<=st.st_size<=max_bytes):
            raise EnrollmentSshError("Unsafe enrollment file")
        with os.fdopen(fd,"rb",closefd=False) as opened:
            data=opened.read(max_bytes+1)
        if len(data)!=st.st_size:
            raise EnrollmentSshError("Enrollment file changed during read")
        return data
    finally:
        os.close(fd)


def b64(text: str, shape: re.Pattern, size: int) -> bytes:
    if not isinstance(text,str) or not shape.fullmatch(text):
        raise EnrollmentSshError("Invalid enrollment encoding")
    try:
        decoded=base64.urlsafe_b64decode(text+"="*((-len(text))%4))
    except (ValueError,base64.binascii.Error) as exc:
        raise EnrollmentSshError("Invalid enrollment encoding") from exc
    if len(decoded)!=size or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()!=text:
        raise EnrollmentSshError("Noncanonical enrollment encoding")
    return decoded


def canonical_message(challenge: dict) -> bytes:
    return json.dumps([
        "MNEBYVPN_ENROLL_CHALLENGE_V1",challenge["nodeId"],
        challenge["endpointHost"],challenge["publicSpki"],
        challenge["challengeId"],challenge["nonce"],challenge["expiresAt"],
    ],separators=(",",":"),ensure_ascii=False).encode()


def proof_message(proof: dict) -> bytes:
    return json.dumps([
        "MNEBYVPN_NODE_ENROLL_V1",proof["nodeId"],proof["endpointHost"],
        proof["publicSpki"],proof["challengeId"],proof["nonce"],
    ],separators=(",",":"),ensure_ascii=False).encode()


def openssl_verify(public_path: Path, signed: bytes, message: bytes) -> None:
    # Ed25519 is a one-shot OpenSSL operation and requires a sized input file.
    # The temporary directory is private (0700), contains NO private keys,
    # and is destroyed even when verification fails.
    with tempfile.TemporaryDirectory(prefix="nodekit-enrollment-") as tmp:
        sig=Path(tmp)/"signature"
        data=Path(tmp)/"message"
        sig.write_bytes(signed)
        data.write_bytes(message)
        sig.chmod(0o600)
        data.chmod(0o600)
        verified=subprocess.run([
            "/usr/bin/openssl","pkeyutl","-verify",
            "-pubin","-inkey",str(public_path),"-keyform","DER",
            "-rawin","-in",str(data),"-sigfile",str(sig),
        ],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            timeout=7,check=False)
    if verified.returncode!=0:
        raise EnrollmentSshError("Controller challenge signature invalid")


def openssl_sign(private_path: Path, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="nodekit-enrollment-") as tmp:
        data=Path(tmp)/"message"
        data.write_bytes(message)
        data.chmod(0o600)
        signed=subprocess.run([
            "/usr/bin/openssl","pkeyutl","-sign",
            "-inkey",str(private_path),"-keyform","DER","-rawin",
            "-in",str(data),
        ],capture_output=True,timeout=7,check=True).stdout
    if len(signed)!=64:
        raise EnrollmentSshError("Invalid node signing result")
    return signed


def sign_challenge(
    challenge: dict, node_dir: Path, expected_identity_sha: str,
    expected_controller_sha: str, now: dt.datetime | None=None,
) -> dict:
    if not isinstance(challenge,dict) or set(challenge)!=FIELDS:
        raise EnrollmentSshError("Unexpected signed challenge fields")
    if (challenge["nodeId"]!=NODE or challenge["endpointHost"]!=HOST or
            not isinstance(expected_identity_sha,str) or
            not SHA.fullmatch(expected_identity_sha) or
            not isinstance(expected_controller_sha,str) or
            not SHA.fullmatch(expected_controller_sha) or
            not UUID.fullmatch(str(challenge["challengeId"]))):
        raise EnrollmentSshError("Unapproved FI enrollment identity or fingerprint")
    public=b64(challenge["publicSpki"],B64_59,44)
    if not public.startswith(SPKI_HEADER):
        raise EnrollmentSshError("Expected Ed25519 node public SPKI")
    nonce=b64(challenge["nonce"],B64_43,32)
    signature=b64(challenge["controllerSignature"],B64_86,64)
    if len(nonce)!=32:
        raise EnrollmentSshError("Invalid nonce")
    if not isinstance(challenge["expiresAt"],str) or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z",
            challenge["expiresAt"]):
        raise EnrollmentSshError("Noncanonical UTC challenge expiry")
    try:
        expires=dt.datetime.fromisoformat(challenge["expiresAt"].replace("Z","+00:00"))
    except ValueError as exc:
        raise EnrollmentSshError("Invalid challenge expiry") from exc
    current=now or dt.datetime.now(dt.timezone.utc)
    if expires<=current or expires>current+dt.timedelta(minutes=5):
        raise EnrollmentSshError("Expired or future-dated challenge")
    private_dir(node_dir)
    identity=node_dir/"identity"
    private_dir(identity)
    meta=json.loads(private_file(node_dir/"manifest.json",max_bytes=10000))
    if (meta.get("node_id")!=NODE or meta.get("advertise_host")!=HOST or
            meta.get("state")!="testing" or
            meta.get("registration_enabled") is not False or
            meta.get("activation_enabled") is not False):
        raise EnrollmentSshError("Node is not in approved testing state")
    node_pub_path=identity/"node-public.spki"
    on_node_pub=private_file(node_pub_path,max_bytes=100)
    if on_node_pub!=public or hashlib.sha256(on_node_pub).hexdigest()!=expected_identity_sha:
        raise EnrollmentSshError("Node identity differs from approved inventory")
    controller_path=node_dir/"controller-access.spki"
    controller_pub=private_file(controller_path,max_bytes=100)
    if (len(controller_pub)!=44 or not controller_pub.startswith(SPKI_HEADER) or
            hashlib.sha256(controller_pub).hexdigest()!=expected_controller_sha):
        raise EnrollmentSshError("Controller key differs from independent pin")
    openssl_verify(controller_path,signature,canonical_message(challenge))
    private_path=identity/"node-private.pk8"
    private_file(private_path,max_bytes=256)
    proof={key:challenge[key] for key in (
        "challengeId","nodeId","endpointHost","publicSpki","nonce")}
    proof["signature"]=base64.urlsafe_b64encode(
        openssl_sign(private_path,proof_message(proof))).rstrip(b"=").decode()
    return proof


def unique_json_pairs(pairs: list[tuple[str, object]]) -> dict:
    # Reject duplicate JSON field names; no parser-dependent reinterpretation
    # of a signed challenge is allowed.
    result={}
    for key,value in pairs:
        if key in result:
            raise EnrollmentSshError("Duplicate enrollment JSON field")
        result[key]=value
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id",required=True)
    parser.add_argument("--expected-identity-sha256",required=True)
    parser.add_argument("--expected-controller-sha256",required=True)
    args=parser.parse_args()
    try:
        if (os.geteuid()!=0 or os.environ.get("SSH_ORIGINAL_COMMAND")!="false" or
                args.node_id!=NODE):
            raise EnrollmentSshError("Forced-command root SSH only")
        private_dir(ROOT)
        raw=sys.stdin.buffer.read(2049)
        if len(raw)>2048 or not raw.endswith(b"\n"):
            raise EnrollmentSshError("Oversized or malformed enrollment request")
        challenge=json.loads(raw,object_pairs_hook=unique_json_pairs)
        proof=sign_challenge(challenge,ROOT/NODE,args.expected_identity_sha256,
                             args.expected_controller_sha256)
        sys.stdout.write(json.dumps(proof,separators=(",",":"),sort_keys=True)+"\n")
        return 0
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        print("NODEKIT_ENROLLMENT_ERROR="+type(exc).__name__,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
