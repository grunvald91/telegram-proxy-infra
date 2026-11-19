#!/usr/bin/env python3
"""FI217 controller -> forced SSH -> node Ed25519 proof, without DB writes.

This is a signed, non-enrollment diagnostic: its challenge UUID and nonce are
NEVER inserted into PostgreSQL, so the proof cannot complete DB enrollment.
Neither private key, signature, nonce, request nor response is logged.
Only runs as root on RU188 with independently pinned public identities.
"""
from __future__ import annotations
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

RU = "188.120.254.223"
FI = "217.11.167.91"
HOST = "fi.mnebyvpn.site"
NODE = "fi-test-01"
ROOT = Path("/root/mnebyvpn-controller")
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class ProbeError(Exception):
    pass


def block(code: str):
    print("FI_SIGNED_PROBE_BLOCKED=" + code, file=sys.stderr)
    raise ProbeError(code)


def is_ru188():
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                data = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s",name.encode()))
                if socket.inet_ntoa(data[20:24]) == RU:
                    return True
            except OSError:
                pass
    return False


def protected(path: Path, max_bytes=8192):
    for directory in path.parents:
        s=directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            block("untrusted_directory")
    fd=os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
                s.st_mode & 0o077 or s.st_nlink != 1 or
                not 1 <= s.st_size <= max_bytes):
            block("untrusted_file")
        data=os.read(fd,max_bytes+1)
        if len(data)!=s.st_size:
            block("unstable_file")
        return data
    finally:
        os.close(fd)


def spki(path,sha):
    data=protected(path,100)
    if len(data)!=44 or not data.startswith(SPKI_PREFIX) or hashlib.sha256(data).hexdigest()!=sha:
        block("unexpected_pinned_public_identity")
    return data


def b64_encode(value: bytes)->str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64_decode(value: str, size: int)->bytes:
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_-]+",value):
        block("invalid_proof_encoding")
    try: decoded=base64.urlsafe_b64decode(value + "="*((-len(value))%4))
    except ValueError: block("invalid_proof_encoding")
    if len(decoded)!=size or b64_encode(decoded)!=value:
        block("noncanonical_proof_encoding")
    return decoded


def canonical_challenge(data: dict)->bytes:
    return json.dumps([
        "MNEBYVPN_ENROLL_CHALLENGE_V1",
        data["nodeId"],data["endpointHost"],data["publicSpki"],
        data["challengeId"],data["nonce"],data["expiresAt"]
    ],ensure_ascii=False,separators=(",",":")).encode()


def canonical_proof(data: dict)->bytes:
    return json.dumps([
        "MNEBYVPN_NODE_ENROLL_V1",
        data["nodeId"],data["endpointHost"],data["publicSpki"],
        data["challengeId"],data["nonce"]
    ],ensure_ascii=False,separators=(",",":")).encode()


def openssl(args: list[str],timeout=7)->subprocess.CompletedProcess:
    try:
        r=subprocess.run(["/usr/bin/openssl",*args],capture_output=True,timeout=timeout,
                         check=False)
    except (OSError,subprocess.TimeoutExpired):
        block("local_openssl_unavailable")
    if r.returncode!=0:
        block("local_signature_operation_failed")
    return r


def ssh_args():
    return [
        "/usr/bin/ssh","-F","/dev/null","-T",
        "-o","BatchMode=yes","-o","IdentitiesOnly=yes",
        "-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no",
        "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
        "-o","UserKnownHostsFile="+str(ROOT/"fi-known_hosts"),
        "-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no",
        "-o","HostKeyAlias="+HOST,"-o","HostName="+FI,
        "-o","ForwardAgent=no","-o","ClearAllForwardings=yes",
        "-o","ControlMaster=no","-o","ProxyCommand=none",
        "-o","LogLevel=ERROR","-o","ConnectTimeout=8",
        "-i",str(ROOT/"fi-enrollment-ssh"),"root@"+HOST,"false"
    ]


def make_challenge(public: bytes, now: dt.datetime, ttl_seconds=150):
    if ttl_seconds not in (150,300):
        block('unreviewed_probe_ttl')
    return {
        "nodeId":NODE,
        "endpointHost":HOST,
        "publicSpki":b64_encode(public),
        "challengeId":str(uuid.uuid4()),
        "nonce":b64_encode(secrets.token_bytes(32)),
        # A shorter window tolerates modest clock differences in both directions
        # while remaining inside the forced handler's maximum five-minute TTL.
        "expiresAt":(now+dt.timedelta(seconds=ttl_seconds)).isoformat(timespec="milliseconds").replace("+00:00","Z"),
    }


def diagnose_stderr(stderr: str):
    if "NODEKIT_ENROLLMENT_ERROR=EnrollmentSshError" in stderr:
        block("fi_handler_rejected_signed_challenge")
    if "NODEKIT_ENROLLMENT_ERROR=CalledProcessError" in stderr:
        block("fi_handler_crypto_command_failed")
    if "NODEKIT_ENROLLMENT_ERROR=" in stderr:
        block("fi_handler_rejected_request")
    if "Permission denied" in stderr:
        block("fi_dedicated_ssh_auth_denied")
    if "Host key verification failed" in stderr:
        block("fi_host_pin_verification_failed")
    if "Connection timed out" in stderr or "Connection refused" in stderr:
        block("fi_ssh_unreachable")
    block("fi_ssh_signed_probe_failed_unclassified")


def main():
    if not is_ru188():
        block("wrong_trusted_controller")
    node_public=spki(ROOT/"fi-node-public.spki",NODE_SHA)
    spki(ROOT/"controller-public.spki",CONTROLLER_SHA)
    protected(ROOT/"controller-signing-key.pem",8192)
    protected(ROOT/"fi-enrollment-ssh",8192)
    known=protected(ROOT/"fi-known_hosts",512).decode("ascii")
    if len(known.splitlines())!=1 or not known.startswith(HOST+" ssh-ed25519 "):
        block("fi_ssh_host_key_not_pinned")
    ttl=300 if sys.argv[1:]==["--max-ttl"] else 150
    if sys.argv[1:] and sys.argv[1:]!=["--max-ttl"]:
        block("unsupported_probe_mode")
    challenge=make_challenge(node_public,dt.datetime.now(dt.timezone.utc),ttl)
    msg=canonical_challenge(challenge)
    with tempfile.TemporaryDirectory(prefix="fi-public-probe-",dir="/run") as tmp:
        directory=Path(tmp)
        message=directory/"challenge-msg"
        public=directory/"controller-public.spki"
        message.write_bytes(msg)
        public.write_bytes(protected(ROOT/"controller-public.spki",100))
        signature=openssl(["pkeyutl","-sign","-inkey",
                           str(ROOT/"controller-signing-key.pem"),"-rawin","-in",str(message)]).stdout
        if len(signature)!=64:
            block("controller_signer_not_ed25519")
        signed=directory/"controller-signature"
        signed.write_bytes(signature)
        openssl(["pkeyutl","-verify","-pubin","-inkey",str(public),
                 "-keyform","DER","-rawin","-in",str(message),"-sigfile",str(signed)])
        challenge["controllerSignature"]=b64_encode(signature)
        try:
            request=json.dumps(challenge,ensure_ascii=False,separators=(",",":"))+"\n"
            ssh=subprocess.run(ssh_args(),input=request,text=True,capture_output=True,
                               timeout=20,check=False)
        except (OSError,subprocess.TimeoutExpired):
            block("dedicated_ssh_transport_unavailable")
        if ssh.returncode!=0:
            diagnose_stderr(ssh.stderr)
        if len(ssh.stdout.encode())>2048 or not ssh.stdout.endswith("\n"):
            block("signed_proof_response_malformed")
        try: proof=json.loads(ssh.stdout)
        except (ValueError,TypeError):
            block("signed_proof_response_malformed")
        fields={"challengeId","nodeId","endpointHost","publicSpki","nonce","signature"}
        if (not isinstance(proof,dict) or set(proof)!=fields or
                any(proof.get(key)!=challenge[key] for key in
                    ("challengeId","nodeId","endpointHost","publicSpki","nonce")) or
                json.dumps(proof,sort_keys=True,separators=(",",":"))+"\n"!=ssh.stdout):
            block("signed_proof_response_mismatch")
        sig=b64_decode(proof["signature"],64)
        sigfile=directory/"node-signature"
        nodefile=directory/"node-public.spki"
        proof_msg=directory/"node-proof-msg"
        sigfile.write_bytes(sig)
        nodefile.write_bytes(node_public)
        proof_msg.write_bytes(canonical_proof(proof))
        openssl(["pkeyutl","-verify","-pubin","-inkey",str(nodefile),
                 "-keyform","DER","-rawin","-in",str(proof_msg),"-sigfile",str(sigfile)])
    print("FI_SIGNED_PROBE=proof_verified;DB_WRITES_BY_PROBE=none;CLIENTS_PUBLISHED=false;TTL_SECONDS="+str(ttl))


if __name__=="__main__":
    try: main()
    except (OSError,UnicodeError,ValueError,TypeError,ProbeError):
        raise SystemExit(2)
