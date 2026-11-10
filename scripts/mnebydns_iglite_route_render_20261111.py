#!/usr/bin/env python3
"""Render a NO-LIVE-CHANGE, exact Instagram Lite DoT->DE->Meta TLS route.

Reuses tested exact-host CoreDNS/Nginx renderer under strict fixed host/IP
constraints. The result is a PILOT ONLY; never write live config here.
"""
from __future__ import annotations
import argparse
import importlib.util
from pathlib import Path
import sys

HOST="iglite-z.instagram.com"
META_ORIGIN="57.144.244.32"
EDGE="89.125.90.101"
BASE=Path(__file__).resolve().parent
_SOURCE=BASE/"mnebydns-owner-domain-render-20261110.py"
spec=importlib.util.spec_from_file_location("exact_route",_SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("Missing tested exact-host renderer")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def render(core:str, nginx:str) -> tuple[str,str]:
    assert m.validate_domain(HOST)==HOST
    assert m.validated_public_ip(META_ORIGIN)==META_ORIGIN
    assert EDGE==m.EDGE
    c=m.core_add(core,HOST)
    n=m.nginx_add(nginx,HOST,META_ORIGIN)
    if m.core_remove(c,HOST)!=core or m.nginx_remove(n,HOST)!=nginx:
        raise AssertionError("Exact-host renderer did not roundtrip cleanly")
    if c.count("match ^iglite-z[.]instagram[.]com[.]$")!=5:
        raise AssertionError("Must match exactly five DNS response types")
    if n.count("        "+HOST+" "+META_ORIGIN+":443;")!=1:
        raise AssertionError("Expected only one exact-host Nginx SNI route")
    for unsafe in ("*.instagram.com","*.facebook.com","~iglite","default "+META_ORIGIN):
        if c.count(unsafe)!=core.count(unsafe) or n.count(unsafe)!=nginx.count(unsafe):
            raise AssertionError("Unsafe wildcard/regex/default route detected")
    return c,n

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--core",required=True)
    ap.add_argument("--nginx",required=True)
    ap.add_argument("--out-dir",required=True)
    args=ap.parse_args()
    dest=Path(args.out_dir)
    if not dest.is_dir() or dest.is_symlink():
        raise ValueError("Output staging directory must be a real directory")
    core=Path(args.core).read_text()
    nginx=Path(args.nginx).read_text()
    new_core,new_nginx=render(core,nginx)
    for name,data in (("Corefile.iglite.preview",new_core),("nginx.conf.iglite.preview",new_nginx)):
        target=dest/name
        if target.exists() or target.is_symlink():
            raise ValueError("Refuse to overwrite any preview")
        target.write_text(data)
    print("iglite_preview=RENDERED_ONLY_NO_LIVE_CHANGES",flush=True)
    print("iglite_exact_host="+HOST,flush=True)
    print("iglite_dns_edge="+EDGE,flush=True)
    print("iglite_verified_meta_origin="+META_ORIGIN,flush=True)

if __name__=="__main__":
    main()
