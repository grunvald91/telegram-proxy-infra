#!/usr/bin/env python3
"""Temporary AWG 3.1 dataplane test on ONE unpublished VPS using a netns client.

No customer key or controller grant is created. No NAT, forwarding, firewall,
external DNS or existing subscriptions are changed. Test-only client private
key stays on VPS in a 0700 scratch folder and is destroyed on cleanup.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from awg_lifecycle import AWG_BIN, active_unit, enabled_unit, unit_name, validate
from install_components import node_ready, safe_dir, safe_manifest

ROOT=Path("/var/lib/mnebyvpn-nodekit")
NETNS="mneby-awg-canary"
VETH_HOST="nkitawg0"
VETH_PEER="nkitawg1"
LINK_HOST="198.19.254.1/30"
LINK_PEER="198.19.254.2/30"
TEST_IP="10.73.91.2"
KEY=re.compile(r"[A-Za-z0-9+/]{43}=\Z")


class NetnsCanaryError(ValueError):
    pass


def run(cmd:list[str],*,timeout=15,check=True,input=None):
    return subprocess.run(cmd,capture_output=True,text=True,check=check,
                          timeout=timeout,input=input,env={**os.environ,
                          "PATH":"/opt/mnebyvpn-amneziawg:/usr/sbin:/usr/bin:/sbin:/bin",
                          "WG_QUICK_USERSPACE_IMPLEMENTATION":
                              "/opt/mnebyvpn-amneziawg/amneziawg-go"})


def ns(*parts:str)->list[str]:
    return ["ip","netns","exec",NETNS,*parts]


def cli_preflight(node:Path,host:str) -> None:
    if os.geteuid()!=0 or node.name!="fi-test-01" or host!="fi.mnebyvpn.site":
        raise NetnsCanaryError("This network namespace test is FI-only")
    validate(node)
    manifest=safe_manifest(node/"manifest.json")
    if (manifest.get("advertise_host")!=host or
        manifest.get("registration_enabled") is not False or
        manifest.get("activation_enabled") is not False):
        raise NetnsCanaryError("Cannot test enabled or foreign node")
    if (active_unit(unit_name(node.name)) or enabled_unit(unit_name(node.name)) or
        active_unit("mnebyvpn-nodekit-awg-watchdog@"+node.name+".service") or
        enabled_unit("mnebyvpn-nodekit-awg-watchdog@"+node.name+".service")):
        raise NetnsCanaryError("Cannot test an active client AWG service")
    if any(x.split()[0]==NETNS for x in run(["ip","netns","list"]).stdout.splitlines()):
        raise NetnsCanaryError("Testing network namespace already exists")
    for iface in (VETH_HOST,VETH_PEER,"awgclient","awg0"):
        if run(["ip","link","show","dev",iface],check=False).returncode==0:
            raise NetnsCanaryError("Testing interface collides with host")
    if run(["ip","route","show","198.19.254.0/30"]).stdout.strip():
        raise NetnsCanaryError("Testing link network would collide with host route")
    if not (AWG_BIN/"awg").is_file() or not (AWG_BIN/"awg-quick").is_file():
        raise NetnsCanaryError("Official AmneziaWG tools not installed")


def get_server_values(node:Path) -> tuple[str,str]:
    cfg=(node/"amneziawg"/"awg0.conf").read_text()
    stage=safe_manifest(node/"amneziawg"/"manifest.json")
    h=re.search(r"(?m)^HeaderProtectionKey = ([A-Za-z0-9+/]{43}=)$",cfg)
    if not h or not KEY.fullmatch(h.group(1)):
        raise NetnsCanaryError("No pinned AWG header protection key")
    pub=stage.get("server_public_key")
    if not isinstance(pub,str) or not KEY.fullmatch(pub):
        raise NetnsCanaryError("No pinned AWG server public key")
    return pub,h.group(1)


def make_client_config(private:str,server_pub:str,header_key:str)->str:
    if not all(KEY.fullmatch(x) for x in (private,server_pub,header_key)):
        raise NetnsCanaryError("Invalid AWG 3.1 test keys")
    return (
        "# Transient local-only Nodekit AWG test; do not distribute\n"
        "[Interface]\n"
        "Address = 10.73.91.2/24\n"
        "PrivateKey = "+private+"\n"
        "ListenPort = 0\n"
        "MTU = 1280\n"
        "Jc = 0\nJmin = 0\nJmax = 0\n"
        "S1 = 16\nS2 = 16\nS3 = 16\nS4 = 16\n"
        "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
        "HeaderProtectionKey = "+header_key+"\n"
        "RandomTrailers = on\nDisableCookies = off\nTable = off\n"
        "\n[Peer]\nPublicKey = "+server_pub+"\n"
        "Endpoint = 198.19.254.1:51821\n"
        "AllowedIPs = 10.73.91.1/32\n"
        "PersistentKeepalive = 10\n"
    )


def ping_canary(node:Path,host:str)->dict:
    cli_preflight(node,host)
    service=unit_name(node.name)
    server_pub,header_key=get_server_values(node)
    private=run([str(AWG_BIN/"awg"),"genkey"]).stdout.strip()
    public=run([str(AWG_BIN/"awg"),"pubkey"],input=private+"\n").stdout.strip()
    if not KEY.fullmatch(private) or not KEY.fullmatch(public):
        raise NetnsCanaryError("Official client key generation failed")
    scratch=Path(tempfile.mkdtemp(prefix=".awg-netns-",dir=node))
    scratch.chmod(0o700)
    cfg=scratch/"awgclient.conf"
    cfg.write_text(make_client_config(private,server_pub,header_key))
    cfg.chmod(0o600)
    created_ns=False
    created_veth=False
    attempted_start=False
    client_up=False
    test_success=False
    try:
        run(["ip","netns","add",NETNS])
        created_ns=True
        run(["ip","link","add",VETH_HOST,"type","veth","peer","name",VETH_PEER])
        created_veth=True
        run(["ip","link","set",VETH_PEER,"netns",NETNS])
        run(["ip","addr","add",LINK_HOST,"dev",VETH_HOST])
        run(["ip","link","set",VETH_HOST,"up"])
        run(ns("ip","addr","add",LINK_PEER,"dev",VETH_PEER))
        run(ns("ip","link","set","lo","up"))
        run(ns("ip","link","set",VETH_PEER,"up"))
        attempted_start=True
        run(["systemctl","start",service],timeout=40)
        if not active_unit(service):
            raise NetnsCanaryError("AWG server did not start")
        run([str(AWG_BIN/"awg"),"set","awg0","peer",public,
             "allowed-ips",TEST_IP+"/32"])
        # The single ephemeral server peer is not part of billing or the
        # persistent grant ledger. It is removed before service shutdown.
        run(ns(str(AWG_BIN/"awg-quick"),"up",str(cfg)),timeout=40)
        client_up=True
        # Bounded handshake and ICMP test entirely through 198.19.254.0/30.
        reply=run(ns("ping","-n","-c","3","-W","3","-i","0.5",
                     "10.73.91.1"),timeout=20)
        if "3 received" not in reply.stdout and "3 packets received" not in reply.stdout:
            raise NetnsCanaryError("AWG tunnel ICMP replies not received")
        handshake=run([str(AWG_BIN/"awg"),"show","awg0",
                       "latest-handshakes"]).stdout
        observed=False
        for line in handshake.splitlines():
            values=line.split()
            if len(values)==2 and values[0]==public and values[1].isdigit():
                observed=int(values[1])>0
        if not observed:
            raise NetnsCanaryError("AWG encrypted handshake not verified")
        test_success=True
        return {
            "node_id":node.name,"hostname":host,
            "protocol":"AmneziaWG 3.1","namespace_client_verified":True,
            "encrypted_handshake_verified":True,"icmp_replies":3,
            "server_published":False,"public_client_e2e_verified":False,
            "nat_enabled":False,"subscriber_credentials_issued":False,
        }
    finally:
        # Prefer bounded best-effort cleanup; never print private keys.
        if created_ns:
            # Also undo a partially successful awg-quick up that threw.
            run(ns(str(AWG_BIN/"awg-quick"),"down",str(cfg)),
                timeout=30,check=False)
        if attempted_start:
            run([str(AWG_BIN/"awg"),"set","awg0","peer",public,"remove"],
                timeout=10,check=False)
            run(["systemctl","stop",service],timeout=35,check=False)
        if created_veth:
            run(["ip","link","del",VETH_HOST],timeout=12,check=False)
        if created_ns:
            run(["ip","netns","del",NETNS],timeout=12,check=False)
        shutil.rmtree(scratch,ignore_errors=True)
        if attempted_start and active_unit(service):
            raise NetnsCanaryError("AWG test did not stop cleanly")
        if test_success and run(["ip","netns","list"]).stdout.find(NETNS)>=0:
            raise NetnsCanaryError("Test namespace cleanup incomplete")
        if test_success and run(["ip","link","show","dev",VETH_HOST],
                                check=False).returncode==0:
            raise NetnsCanaryError("Test veth cleanup incomplete")


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node-id",required=True)
    ap.add_argument("--host",required=True)
    ap.add_argument("--stage-root",type=Path,default=ROOT)
    args=ap.parse_args()
    try:
        if os.geteuid()!=0:
            raise NetnsCanaryError("Root required")
        node=node_ready(args.stage_root,args.node_id)
        print(json.dumps(ping_canary(node,args.host),sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        print("nodekit_awg_netns_canary_error="+type(exc).__name__,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
