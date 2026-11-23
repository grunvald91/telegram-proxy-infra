#!/usr/bin/env python3
"""Durable high-water revision for FI217 personal DoT signed controller policy.

Root-only disk fence; no service or public socket starts. This fencing does
not authenticate the snapshot: ONLY call after verifying Ed25519 and TTL.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from fi_dns_signed_grants import (
    RegionalDnsGrantError, message,
)

SHA_LENGTH = 64
MAX_RECORD_SIZE = 256
FIELDS = frozenset(("version", "revision", "transcriptSha256"))


def deny() -> None:
    raise RegionalDnsGrantError("Unsafe FI DoT monotonic signed snapshot state")


def _dir_ok(root: Path, owner_uid: int) -> None:
    if root.is_symlink() or not root.is_dir():
        deny()
    info = root.stat()
    if info.st_uid != owner_uid or info.st_mode & 0o077:
        deny()


def _read_record(path: Path, owner_uid: int) -> dict | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        deny()
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or
                info.st_mode & 0o077 or not 1 <= info.st_size <= MAX_RECORD_SIZE):
            deny()
        with os.fdopen(os.dup(fd), "rb") as stream:
            body = stream.read(MAX_RECORD_SIZE + 1)
        if not 1 <= len(body) <= MAX_RECORD_SIZE:
            deny()
        try:
            record = json.loads(body)
        except (ValueError, UnicodeError):
            deny()
        if (not isinstance(record, dict) or set(record) != FIELDS or
                type(record["version"]) is not int or record["version"] != 1 or
                type(record["revision"]) is not int or
                not 1 <= record["revision"] <= 1_000_000_000 or
                not isinstance(record["transcriptSha256"], str) or
                len(record["transcriptSha256"]) != SHA_LENGTH or
                any(c not in "0123456789abcdef"
                    for c in record["transcriptSha256"])):
            deny()
        return record
    finally:
        os.close(fd)


def signed_revision_record(snapshot: dict) -> dict:
    """Hash signed transcript, NOT arbitrary JSON envelope whitespace."""
    return {
        "version": 1,
        "revision": snapshot["revision"],
        "transcriptSha256": hashlib.sha256(message(snapshot)).hexdigest(),
    }


class Highwater:
    def __init__(self, path: Path, *, owner_uid: int = 0):
        self.path = path
        self.owner_uid = owner_uid

    def observe(self, snapshot: dict) -> None:
        _dir_ok(self.path.parent, self.owner_uid)
        current = signed_revision_record(snapshot)
        previous = _read_record(self.path, self.owner_uid)
        if previous:
            if current["revision"] < previous["revision"]:
                deny()
            if current["revision"] == previous["revision"]:
                if current["transcriptSha256"] != previous["transcriptSha256"]:
                    deny()
                return

        record = (json.dumps(current, separators=(",", ":"), sort_keys=True)
                  + "\n").encode("ascii")
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.path.parent, prefix=".fi-dot-highwater-",
                delete=False,
            ) as file:
                tmp_name = file.name
                os.fchmod(file.fileno(), 0o600)
                file.write(record)
                file.flush()
                os.fsync(file.fileno())
            # Symlink swaps are denied by the next open through O_NOFOLLOW.
            # The containing directory is root-only and inaccessible to users.
            os.replace(tmp_name, self.path)
            tmp_name = None
            dirfd = os.open(self.path.parent,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if tmp_name is not None:
                Path(tmp_name).unlink(missing_ok=True)
