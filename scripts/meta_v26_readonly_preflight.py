#!/usr/bin/env python3
"""Actual DE/RU v26 safe preflight. No live production configuration writes."""
from __future__ import annotations
import argparse
import tempfile
from pathlib import Path

import meta_v26_de_stage as de
import meta_v26_ru_stage as ru
from meta_v25_source_view import render
from meta_v23_ru_firsthop_preview import HOSTS,load_renderer

def audit_de():
    de.guards()
    if de.ROOT.exists() or de.active(de.UNIT+".timer"):
        raise RuntimeError("prior DE trial still owns state")
    live_dns=de.LIVE_DNS.read_text()
    live_ng=de.LIVE_NGINX.read_text()
    plan=render(corefile=live_dns,phone_ip="8.8.8.8",
                compiled_plugins=de.compiled_plugins())
    plan.verify_rollback()
    owner=load_renderer()
    mapping={}
    nginx=live_ng
    for host in HOSTS:
        # A public IP alone is insufficient: owner.origin_ip verifies TLS cert.
        mapping[host]=owner.origin_ip(host)
        nginx=owner.nginx_add(nginx,host,mapping[host])
    reverse=nginx
    for host in reversed(HOSTS):
        reverse=owner.nginx_remove(reverse,host)
    if reverse!=live_ng:raise RuntimeError("Nginx exact SNI routes not reversible")
    # Test generated config without touching the running service.
    with tempfile.TemporaryDirectory(prefix="mneby-v26-nginx-check-") as tmp:
        path=Path(tmp)/"nginx.conf"
        path.write_text(nginx)
        path.chmod(0o600)
        de.cmd(["nginx","-t","-c",str(path)],timeout=25)
    print("meta_v26_de_live_preflight=PASS",flush=True)
    print("meta_v26_de_exact_tls_verified_origin_count="+str(len(mapping)),flush=True)
    print("meta_v26_de_client_view_ready=true",flush=True)
    print("meta_v26_de_nginx_candidate_syntax=PASS",flush=True)
    print("meta_v26_de_no_prod_writes=true",flush=True)

def audit_ru():
    ru.baseline("8.8.8.8")
    print("meta_v26_ru_live_preflight=PASS",flush=True)
    print("meta_v26_ru_wg_route=PASS",flush=True)
    print("meta_v26_ru_nft_dry_validation=PASS",flush=True)
    print("meta_v26_ru_receiver_port_free=true",flush=True)
    print("meta_v26_ru_no_prod_writes=true",flush=True)

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("role",choices=("de","ru"))
    args=parser.parse_args()
    if args.role=="de":audit_de()
    else:audit_ru()
