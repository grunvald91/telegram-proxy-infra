#!/usr/bin/env python3
"""Permanent routed FI DNS origin + metered TLS runtime. Pilot remains gate OFF."""
from __future__ import annotations
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

from fi_dns_ssh_stage import FI,FI_ROOT,FI_RUNTIME,CONTROLLER_PIN,host,private_dir,read,immutable,require
from fi_dns_origin_canary import prepare,COREDNS,HOSTS,EXTERNAL_QUERY,dot_probe
from fi_regional_cert_stage import DEST as REGIONAL_TLS,verify_pair
from fi_dns_guarded_ingress import SNAPSHOT,CONTROLLER
from fi_dns_signed_grants import validate,verify_signature
from fi_dns_highwater import Highwater
from fi_dns_meter_rpc import protected_openssl_meter,unique_object
from fi_dns_reverse_channel import ReverseTransport,PING_OP,PONG
from fi_dns_metered_dot import LoopbackTlsResolver
from fi_dns_tls_session import SignedFiGrantAuthorizer,make_metered_loopback_server

STATE=FI_ROOT/"dns-auth"
CONFIG=STATE/"RoutedCorefile"
MARKER=STATE/"routed-dataplane.enable"
RECEIVE_HIGHWATER=STATE/"receiver-highwater.json"

def corefile_bytes(original):
    text=original.decode("ascii")
    old="  tls "+str(FI_ROOT/"tls/fullchain.pem")+" "+str(FI_ROOT/"tls/privkey.pem")
    new="  tls "+str(REGIONAL_TLS/"fullchain.pem")+" "+str(REGIONAL_TLS/"privkey.pem")
    require(text.count(old)==1,"origin_tls_mismatch")
    require("tls://.:8853 {" in text and "  bind 127.0.0.1" in text,"origin_not_loopback")
    require("  forward . tls://1.1.1.1 tls://1.0.0.1 {" in text,"origin_forwarder_mismatch")
    return text.replace(old,new).encode("ascii")

def atomic_snapshot(path,raw):
    # Caller has already verified signature, freshness and monotonic revision.
    private_dir(path.parent)
    if path.exists() or path.is_symlink():read(path,700000)
    fd,tmp=tempfile.mkstemp(prefix=".private-fi-snapshot-",dir=path.parent)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:Path(tmp).unlink(missing_ok=True)

def accept_snapshot(raw, *, now=None, path=SNAPSHOT, highwater=None, verifier=verify_signature):
    policy=validate(json.loads(raw,object_pairs_hook=unique_object),time.time() if now is None else now)
    verifier(policy,CONTROLLER,CONTROLLER_PIN)
    # Separate later public release required. Fail closed even if another
    # operator accidentally enables the controller gate while still staging.
    require(policy["grants"]==[],"private_stage_requires_empty_grants")
    fence=highwater if highwater is not None else Highwater(RECEIVE_HIGHWATER)
    fence.observe(policy)
    atomic_snapshot(path,raw)
    return policy["revision"]

async def refresh(transport):
    raw=await transport.snapshot()
    await asyncio.to_thread(accept_snapshot,raw)

async def refresh_loop(transport):
    while True:
        await asyncio.sleep(15)
        try:await refresh(transport)
        except (OSError,ValueError,RuntimeError,TypeError,asyncio.IncompleteReadError):
            # Existing signed empty policy cannot grant anything and expires.
            print("FI_PRIVATE_SNAPSHOT_REFRESH_FAILED",flush=True)

async def run():
    host(FI);private_dir(STATE)
    require(read(MARKER,100)==b"fi-dns-routed-v2\n","private_stage_marker_missing")
    verify_pair(REGIONAL_TLS)
    require(read(STATE/"PrivateCorefile",120000)==corefile_bytes(prepare().read_bytes()),"private_origin_drift")
    from fi_shared_routes import render_core,hostname
    bundle=STATE/"shared-routes"
    private_dir(bundle)
    report=json.loads(read(bundle/"manifest.json",10000))
    require(report.get("local_canary_verified") is True and report.get("public_activation") is False,"unverified_route_bundle")
    for name in ("policy.json","Corefile","nginx.conf"):
        require(hashlib.sha256(read(bundle/name,500000)).hexdigest()==report["config_sha256"][name],"route_bundle_hash_mismatch")
    policy=json.loads(read(bundle/"policy.json",500000))
    require(len(policy["exact"])==report["exact_count"] and len(policy["families"])==report["family_count"],"route_count_mismatch")
    for name in policy["exact"]+policy["families"]:hostname(name)
    candidate=render_core(policy,read(STATE/"PrivateCorefile",120000).decode("ascii"))
    require(candidate.encode()==read(bundle/"Corefile",500000),"route_renderer_drift")
    require(read(CONFIG,500000)==candidate.replace("tls://.:18855 {","tls://.:8853 {").encode(),"routed_origin_drift")
    transport=ReverseTransport()
    require(await transport.exchange(PING_OP,timeout=8)==PONG,"reverse_channel_unavailable")
    await refresh(transport)
    meter=protected_openssl_meter(transport,FI_ROOT/"identity/node-private.pk8",CONTROLLER,CONTROLLER_PIN)
    authorizer=SignedFiGrantAuthorizer(CONTROLLER_PIN)
    require(not await authorizer.allowed(HOSTS[0]),"private_gate_not_closed")
    child=await asyncio.create_subprocess_exec(str(COREDNS),"-conf",str(CONFIG),
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    server=None
    jobs=[]
    try:
        for _ in range(15):
            if child.returncode is not None:raise RuntimeError("private_origin_exited")
            try:
                if await asyncio.to_thread(dot_probe,HOSTS[0],EXTERNAL_QUERY):break
            except (OSError,ValueError):pass
            await asyncio.sleep(.5)
        else:raise RuntimeError("private_origin_not_ready")
        server=await make_metered_loopback_server(authorizer=authorizer,meter=meter,
            resolver=LoopbackTlsResolver(HOSTS[0]))
        print("FI_ROUTED_DATAPLANE_READY=true",flush=True)
        stop=asyncio.Event()
        loop=asyncio.get_running_loop()
        for sig in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(sig,stop.set)
        jobs=[asyncio.create_task(refresh_loop(transport)),asyncio.create_task(child.wait()),
              asyncio.create_task(stop.wait())]
        done,_=await asyncio.wait(jobs,return_when=asyncio.FIRST_COMPLETED)
        if jobs[2] not in done:raise RuntimeError("private_dataplane_child_stopped")
    finally:
        for job in jobs:job.cancel()
        await asyncio.gather(*jobs,return_exceptions=True)
        if server is not None:server.close();await server.wait_closed()
        if child.returncode is None:
            child.terminate()
            try:await asyncio.wait_for(child.wait(),5)
            except asyncio.TimeoutError:child.kill();await child.wait()

if __name__=="__main__":
    try:
        os.umask(0o077)
        asyncio.run(run())
    except (OSError,ValueError,RuntimeError,TypeError,subprocess.SubprocessError,asyncio.IncompleteReadError):
        print("FI_ROUTED_DATAPLANE_STOPPED",file=sys.stderr,flush=True)
        raise SystemExit(2)
