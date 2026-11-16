#!/usr/bin/env python3
"""Guarded atomic file publish for existing owner-domain stage/rollback.

Only called by the owner-domain controller while it holds the shared
/run/lock/mnebyvpn-public-route.lock. Keeps the controller's existing
durable systemd rollback and single-domain authorization checks intact.
Never prints any DNS content.
"""
import os
from pathlib import Path
import stat
import sys

from mnebydns_nov8_restore_safety import atomic_replace, capture, digest

ALLOW={
    "dns":Path("/opt/mnebydns-dot/Corefile"),
    "shared":Path("/etc/nginx/nginx.conf"),
}
LOCK=Path("/run/lock/mnebyvpn-public-route.lock")
CHECKPOINT=Path("/opt/mnebydns-owner-domain")


def safe_swap(kind, basename, expected_name, candidate_name):
    if os.geteuid()!=0 or kind not in ALLOW:
        raise PermissionError("Restricted root-only owner-domain update")
    # Parent shell holds the lock open as fd 9 for the entire canary operation.
    inherited=os.fstat(9)
    guard=LOCK.stat()
    if (inherited.st_dev,inherited.st_ino)!=(guard.st_dev,guard.st_ino):
        raise RuntimeError("Shared route lock was not inherited")
    base=Path(basename)
    if (base.is_symlink() or not base.is_dir() or
        base.resolve().parent!=CHECKPOINT.resolve() or
        not base.name.isdigit() or not 9<=len(base.name)<=13):
        raise RuntimeError("Invalid owner-domain checkpoint")
    if expected_name not in ("dns.before","dns.pilot","nginx.before","nginx.pilot") or \
       candidate_name not in ("dns.before","dns.pilot","nginx.before","nginx.pilot"):
        raise ValueError("Unexpected checkpoint filename")
    prefix="dns" if kind=="dns" else "nginx"
    if not expected_name.startswith(prefix+".") or not candidate_name.startswith(prefix+"."):
        raise ValueError("Checkpoint kind does not match live file")
    expected=base/expected_name
    candidate=base/candidate_name
    if (expected.is_symlink() or candidate.is_symlink() or
        not expected.is_file() or not candidate.is_file()):
        raise RuntimeError("No regular owner-domain candidate")
    actual=capture(ALLOW[kind])
    original=expected.read_bytes()
    proposed=candidate.read_bytes()
    if actual.sha256!=digest(original):
        raise RuntimeError("Config changed since owner-domain stage; refusing publish")
    if not proposed or len(proposed)>700000:
        raise RuntimeError("Invalid candidate length")
    atomic_replace(ALLOW[kind],actual,proposed)
    print("MNEBYDNS_OWNER_ATOMIC_"+kind.upper()+"=OK")


if __name__=="__main__":
    if len(sys.argv)!=5:
        raise SystemExit("Usage: kind base expected_name candidate_name")
    safe_swap(*sys.argv[1:])
