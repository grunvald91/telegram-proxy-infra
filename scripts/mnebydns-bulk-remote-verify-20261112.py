#!/usr/bin/env python3
"""Remote safety check: exact bulk manifest produces ONLY the supplied additive pilots.

Do not use this module to activate a route. Requires current baseline hashes
provided by the live preflight; no DNS/HTTP/SQL operations performed.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def check(work: Path, base: Path):
    if work.is_symlink() or base.is_symlink():
        raise ValueError("Symlink refused")
    rf=work/"mnebydns-owner-domain-render-20261110.py"
    spec=importlib.util.spec_from_file_location("owner_bulk_renderer", rf)
    if spec is None or spec.loader is None:
        raise RuntimeError("Missing exact hostname renderer")
    policy=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    expected=json.loads((work/"expected.json").read_text())
    manifest=(work/"manifest.tsv").read_text().splitlines()
    if not 1<=len(manifest)<=102 or len(set(manifest))!=len(manifest):
        raise RuntimeError("Invalid or duplicate bulk entries")
    if len(manifest)!=expected.get("eligible") or expected.get("no_live_mutations") is not True:
        raise RuntimeError("Unexpected preflight scope")
    c=(base/"dns.before").read_text()
    n=(base/"nginx.before").read_text()
    if sha(c)!=expected["source_sha256"]["core"] or sha(n)!=expected["source_sha256"]["nginx"]:
        raise RuntimeError("Live checkpoint changed after preflight")
    for item in manifest:
        parts=item.split("\t")
        if len(parts)!=2:
            raise RuntimeError("Malformed exact-domain row")
        host=policy.validate_domain(parts[0])
        ip=policy.validated_public_ip(parts[1])
        c=policy.core_add(c,host)
        n=policy.nginx_add(n,host,ip)
        if c.count(policy.mark(host))!=2 or n.count(policy.mark(host))!=2:
            raise RuntimeError("Duplicate or missing exact marker")
    if sha(c)!=expected["target_sha256"]["core"] or sha(n)!=expected["target_sha256"]["nginx"]:
        raise RuntimeError("Re-rendered target hashes do not match preflight")
    if (base/"dns.pilot").read_text()!=c or (base/"nginx.pilot").read_text()!=n:
        raise RuntimeError("Transferred pilot content not an exact additive renderer output")
    print("MNEBYDNS_BULK_REMOTE_MANIFEST_VERIFIED="+str(len(manifest)),flush=True)

if __name__=="__main__":
    a=argparse.ArgumentParser()
    a.add_argument("work", type=Path)
    a.add_argument("base", type=Path)
    v=a.parse_args()
    check(v.work,v.base)
