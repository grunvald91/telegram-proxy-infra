#!/usr/bin/env python3
"""Reversible Meta-only DNS + DE origin SNI preview for existing RU->WG->DE.

No ssh, no actual production file writes, no origin-IP discovery. Caller must
supply 11 already TLS-verified public origin IPv4s. This module renders only.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path

import mnebydns_iglite_wifi_multi_meta_v10_w20 as baseline
from meta_v15_receive_window import nft_rules

RU_EDGE = "188.120.254.223"
DE_EDGE = "89.125.90.101"
WG_BACKEND = "10.66.77.1"
RU_INTERFACE = "ens3"
TEST_PORT = 18443
HOSTS = baseline.HOSTS

def load_renderer():
    path=Path(__file__).with_name("mnebydns-owner-domain-render-20261110.py")
    spec=importlib.util.spec_from_file_location("mneby_owner_exact_routes",path)
    if spec is None or spec.loader is None:raise RuntimeError("owner route renderer unavailable")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def render_existing_servers(*, original_core: str, original_de_nginx: str,
                            origins: dict[str,str]):
    """Meta A->RU 188; DE Nginx SNI->TLS-verified origin IP; no RU Nginx edit."""
    if set(origins)!=set(HOSTS) or len(origins)!=len(HOSTS):
        raise ValueError("all 11 exact Meta origins required, no unknown hostnames")
    renderer=load_renderer()
    core=original_core
    nginx=original_de_nginx
    for hostname in HOSTS:
        core=renderer.core_add(core,hostname,route_edge=RU_EDGE)
        nginx=renderer.nginx_add(nginx,hostname,origins[hostname])
    rev_core,rev_nginx=core,nginx
    for hostname in reversed(HOSTS):
        rev_core=renderer.core_remove(rev_core,hostname)
        rev_nginx=renderer.nginx_remove(rev_nginx,hostname)
    if rev_core!=original_core or rev_nginx!=original_de_nginx:
        raise RuntimeError("non-byte-reversible exact-route Meta edits")
    # Require all five type cases per exact host; no wildcard Meta overrides.
    for hostname in HOSTS:
        begin,end=renderer._block_bounds(core,hostname)
        segment=core.split(begin,1)[1].split(end,1)[0]
        if segment.count('answer "{{ .Name }} 20 IN A '+RU_EDGE+'"')!=1:
            raise RuntimeError("RU exact-host A route missing")
        if segment.count("rcode NOERROR")!=4:
            raise RuntimeError("non-A DNS types could bypass RU Meta ingress")
    return core,nginx

def ru_peer_rules(peer: str)->str:
    """Peer scope covers the existing RU public IP only; never global sysctl."""
    rules=nft_rules(RU_EDGE,peer,port=TEST_PORT,
                    interface=RU_INTERFACE,table="mneby_meta_v23_ru")
    if 'iifname "'+RU_INTERFACE+'"' not in rules or 'ip daddr '+RU_EDGE not in rules:
        raise RuntimeError("incorrect RU public interface or edge")
    return rules

def worker_arguments(peer: str)->tuple[str,...]:
    """Dedicated receiver on RU, fixed WG destination (not general proxy)."""
    ru_peer_rules(peer)
    return ("--peer",peer,"--edge",RU_EDGE,"--port",str(TEST_PORT),
            "--backend-address",WG_BACKEND)

if __name__=="__main__":
    print("meta_v23_ru_firsthop_preview=OFFLINE_ONLY")
    print("meta_v23_dns_meta_A_to_RU="+RU_EDGE)
    print("meta_v23_ru_tcp_ingress=ens3:443_to_dedicated_18443")
    print("meta_v23_ru_backend=FIXED_PRIVATE_WIREGUARD_443")
    print("meta_v23_de_nginx_exact_origin_routes=REQUIRED")
    print("meta_v23_android_end_to_end=UNTESTED")
