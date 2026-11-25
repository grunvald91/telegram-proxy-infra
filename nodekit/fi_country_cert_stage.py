#!/usr/bin/env python3
"""FI217 regional DNS TLS *staging only*; never replaces the active country TLS.

Input comes from pinned DE89 SSH over a private CI runner and is installed
atomically as one root-owned directory under the existing FI Nodekit. This
module creates NO systemd unit, listener, entitlement, iptables rule, route,
DNS query, or public certificate path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

NODE = "fi-test-01"
ROOT = Path("/var/lib/mnebyvpn-nodekit") / NODE
DEST = ROOT / "fi-country-tls-v2"
LABEL = "*.fi.mnebyvpn.site"
PROBES = (
    "aaaaaaaaaaaa.fi.mnebyvpn.site",
    "bbbbbbbbbbbb.fi.mnebyvpn.site",
)
CERT = "fullchain.pem"
KEY = "privkey.pem"
MAX_CHAIN = 40000
MAX_KEY = 12000
CAFILE = "/etc/ssl/certs/ca-certificates.crt"


class CertStageError(ValueError):
    pass


def deny(message="FI regional certificate staging blocked"):
    raise CertStageError(message)


def trusted_dir(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        deny("Unsafe certificate directory")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        deny("Unsafe certificate directory permissions")


def trusted_file(path: Path, max_bytes: int) -> bytes:
    # No symlinks, group access, world access, or ownership changes.
    if path.is_symlink() or not path.is_file():
        deny("Unsafe certificate file")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_mode & 0o077 or not 1 <= info.st_size <= max_bytes):
        deny("Unsafe certificate file permissions")
    return path.read_bytes()


def command(args: list[str], *, input: bytes | None = None) -> bytes:
    try:
        done = subprocess.run(args, input=input, timeout=8, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        deny("Regional certificate OpenSSL validation unavailable")
    if done.returncode != 0:
        deny("Invalid regional certificate chain or key")
    return done.stdout


def exact_regional_san(path: Path) -> None:
    san = command(["openssl", "x509", "-in", str(path), "-noout",
                   "-ext", "subjectAltName"]).decode("ascii", "replace")
    hostnames = re.findall(r"DNS:([^,\s]+)", san)
    if LABEL not in hostnames:
        deny("Required FI regional wildcard SAN missing")
    if any("*" in item and item != LABEL for item in hostnames):
        deny("Unapproved wildcard SAN")


def verify_pair(directory: Path) -> dict:
    trusted_dir(directory)
    chain_path = directory / CERT
    key_path = directory / KEY
    chain = trusted_file(chain_path, MAX_CHAIN)
    trusted_file(key_path, MAX_KEY)
    if not chain.startswith(b"-----BEGIN CERTIFICATE-----"):
        deny("Invalid PEM fullchain")
    if chain.count(b"-----BEGIN CERTIFICATE-----") < 2:
        deny("Incomplete regional certificate fullchain")
    exact_regional_san(chain_path)
    command(["openssl", "x509", "-in", str(chain_path), "-noout",
             "-checkend", "1209600"])
    for hostname in PROBES:
        command(["openssl", "verify", "-purpose", "sslserver",
                 "-verify_hostname", hostname,
                 "-CAfile", CAFILE,
                 "-untrusted", str(chain_path), str(chain_path)])
    pub_key = command(["openssl", "pkey", "-in", str(key_path),
                       "-pubout", "-outform", "DER"])
    pub_pem = command(["openssl", "x509", "-pubkey", "-noout",
                       "-in", str(chain_path)])
    cert_pub_key = command(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub_pem)
    if not pub_key or pub_key != cert_pub_key:
        deny("Regional private key does not match leaf certificate")
    return {
        "regional_san_exact": True,
        "trusted_chain_for_two_names": True,
        "certificate_key_match": True,
        "certificate_sha256": hashlib.sha256(chain).hexdigest(),
    }


def stage(source: Path) -> dict:
    if os.geteuid() != 0:
        deny("Root-only stage")
    trusted_dir(ROOT)
    manifest_file = ROOT / "manifest.json"
    manifest = json.loads(trusted_file(manifest_file, 20000))
    if (manifest.get("node_id") != NODE or
            manifest.get("advertise_host") != "fi.mnebyvpn.site" or
            manifest.get("state") not in ("testing", "active")):
        deny("Unapproved FI node identity")
    verified = verify_pair(source)
    if DEST.is_symlink():
        deny("Regional certificate target is a symlink")
    if DEST.exists():
        existing = verify_pair(DEST)
        if existing["certificate_sha256"] != verified["certificate_sha256"]:
            deny("Existing different FI regional certificate; no overwrite")
        return {"regional_fi_certificate_staged": True,
                "change": "UNCHANGED", "public_listener_changed": False,
                "active_country_tls_changed": False}

    tmp: Path | None = None
    try:
        tmp = Path(tempfile.mkdtemp(prefix=".fi-country-tls-v2.", dir=ROOT))
        tmp.chmod(0o700)
        for filename, limit in [(CERT, MAX_CHAIN), (KEY, MAX_KEY)]:
            body = trusted_file(source / filename, limit)
            output = tmp / filename
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as opened:
                opened.write(body)
                opened.flush()
                os.fsync(opened.fileno())
        verify_pair(tmp)
        # Only a brand-new directory is accepted; never replace unknown
        # contents or existing live certificates. Nodekit directory is root-only.
        if DEST.exists() or DEST.is_symlink():
            deny("Concurrent regional certificate stage")
        os.rename(tmp, DEST)
        tmp = None
        dfd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return {"regional_fi_certificate_staged": True, "change": "STAGED",
                "public_listener_changed": False,
                "active_country_tls_changed": False}
    finally:
        if tmp is not None and tmp.is_dir() and not tmp.is_symlink():
            for filename in (CERT, KEY):
                (tmp / filename).unlink(missing_ok=True)
            tmp.rmdir()


def inspect() -> dict:
    if DEST.exists() and not DEST.is_symlink():
        verified = verify_pair(DEST)
        return {"regional_fi_certificate_staged": True,
                "verified": bool(verified), "public_listener_changed": False}
    return {"regional_fi_certificate_staged": False,
            "verified": False, "public_listener_changed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("inspect", "stage"), required=True)
    parser.add_argument("--source-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "stage":
            if args.source_dir is None:
                deny("Source certificate directory required")
            report = stage(args.source_dir)
        else:
            report = inspect()
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError):
        print("FI_REGIONAL_CERT_STAGE_BLOCKED=true", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
