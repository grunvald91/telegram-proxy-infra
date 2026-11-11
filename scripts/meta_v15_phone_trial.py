#!/usr/bin/env python3
"""Owner-requested 900s IPv4 phone canary, explicit peer required.

Reuse the reviewed exact-host v11 route/restore engine and add a separately
supervised receiver-window proxy. No global sysctl or queue210 rule changes.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import time

import mnebydns_iglite_route_only_v11 as route
from meta_v15_receive_window import nft_rules,verify_queue_exemption

STATE=Path("/var/lib/mneby-meta-v15-controller")
STAGE=Path("/usr/local/libexec/mneby-meta-v15")
UNIT="mneby-meta-v15-cleanup"
WORKER="mneby-meta-v15-proxy"
TABLE="mneby_meta_v15"
EDGE="89.125.90.101"
PORT=18443

route.base.ROOT=Path("/var/lib/mneby-meta-v15-routes")
route.base.UNIT="mneby-meta-v15-route-watchdog"
route.base.TABLE="mneby_meta_v15_unexpected_global"
route.base.PERSISTENT_STAGE=STAGE
route.ROLLBACK_SCRIPT=Path(__file__).resolve()
route.TRANSPORT_LABEL="V15_PEER_WINDOW8_NO_GLOBAL_SYSCTL"


def command(*args,**kwargs):return route.base.command(*args,**kwargs)


def cleanup():
    if not (STATE/"armed").is_file():return
    errors=[]
    # Remove redirection first, then close only the dedicated worker sockets.
    try:
        if command(["nft","list","table","inet",TABLE],check=False).returncode==0:
            command(["nft","delete","table","inet",TABLE])
    except Exception:errors.append("nft")
    try:command(["systemctl","stop",WORKER+".service"],timeout=20,check=False)
    except Exception:errors.append("worker")
    try:route.rollback()
    except Exception:errors.append("routes")
    if command(["nft","list","table","inet",TABLE],check=False).returncode==0:
        errors.append("nft_still_present")
    if command(["systemctl","is-active","--quiet",WORKER+".service"],check=False).returncode==0:
        errors.append("worker_still_active")
    if errors:raise RuntimeError("v15 cleanup failed: "+",".join(errors))
    print("meta_v15_cleanup=VERIFIED",flush=True)


def live(peer):
    peer=str(ipaddress.IPv4Address(peer))
    if not ipaddress.IPv4Address(peer).is_global or peer==EDGE:
        raise ValueError("identified test-phone public IPv4 required")
    if os.geteuid()!=0 or Path(__file__).resolve().parent!=STAGE:
        raise RuntimeError("requires root and persistent reviewed stage")
    if os.environ.get("MNEBY_META_V15_APPROVED")!="YES":
        raise RuntimeError("explicit canary flag required")
    for key in ("MNEBY_IGLITE_LIVE_APPROVED","MNEBY_IGLITE_TEMPORARY_ONLY_APPROVED",
                "MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED"):
        os.environ[key]="YES"
    route.check_retired_v10()
    route.base.baseline()
    for unit in (UNIT,WORKER,"mneby-ig-lite-route-only-20261111-v11"):
        for suffix in (".timer",".service"):
            if command(["systemctl","is-active","--quiet",unit+suffix],check=False).returncode==0:
                raise RuntimeError("another experiment unit active")
    if STATE.exists() or command(["nft","list","table","inet",TABLE],check=False).returncode==0:
        raise RuntimeError("prior v15 state exists; refuse duplicate")
    # Verify the actual live queue guard before relying on socket SO_MARK.
    ruleset=json.loads(command(["nft","-j","list","ruleset"]).stdout)
    verify_queue_exemption(ruleset)
    rules=nft_rules(EDGE,peer,port=PORT)
    command(["nft","--check","-f","-"],input=rules)
    if command(["ss","-H","-lnt","sport", "=", ":"+str(PORT)]).stdout.strip():
        raise RuntimeError("dedicated port occupied")
    STATE.mkdir(mode=0o700)
    owner=os.environ.get("MNEBY_META_V15_RUN_ID","manual")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}",owner):
        raise ValueError("invalid run identity")
    route.base.write_exclusive(STATE/"owner",owner.encode("ascii"))
    route.base.write_exclusive(STATE/"peer",peer.encode("ascii"))
    route.base.write_exclusive(STATE/"armed",b"armed\n")
    route.base.fsync_directory(STATE)
    route.base.fsync_directory(STATE.parent)
    old_handlers={sig:signal.signal(sig,route.interrupted)
                  for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    try:
        # Exists independently of SSH and the Python controller. The inner
        # v11 timer also points back to this full cleanup entrypoint.
        route.EXTERNAL_DEADLINE=time.monotonic()+1500
        command(["systemd-run","--quiet","--collect","--unit",UNIT,
                 "--on-active=1500s","/usr/bin/python3",str(Path(__file__).resolve()),"rollback"])
        if command(["systemctl","is-active","--quiet",UNIT+".timer"],check=False).returncode:
            raise RuntimeError("independent full cleanup timer not armed")
        command(["systemd-run","--quiet","--collect","--unit",WORKER,
                 "--property=RuntimeMaxSec=1500","--property=KillMode=control-group",
                 "/usr/bin/python3","-u",str(STAGE/"meta_v15_receive_window.py"),
                 "--peer",peer,"--edge",EDGE,"--port",str(PORT)])
        for _ in range(50):
            if command(["ss","-H","-lnt","sport","=",":"+str(PORT)]).stdout.strip():break
            time.sleep(.1)
        else:raise RuntimeError("dedicated proxy not listening")
        command(["nft","-f","-"],input=rules)
        route.CAPTURE_PEER=peer
        print("meta_v15_mechanism=PER_SOCKET_SCALE0_WINDOW8_UNTIL_SNI",flush=True)
        print("meta_v15_scope=ONE_IPV4_PEER_TCP443",flush=True)
        print("meta_v15_phone_identity=NAT_PEER_ONLY_NOT_DEVICE_PROOF",flush=True)
        route.live()
    finally:
        for sig in old_handlers:signal.signal(sig,signal.SIG_IGN)
        try:cleanup()
        finally:
            for sig,handler in old_handlers.items():signal.signal(sig,handler)
    print("meta_v15_android_bypass=REQUIRES_PHONE_RESULT",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=("live","rollback"))
    parser.add_argument("--peer")
    args=parser.parse_args()
    if args.mode=="rollback":cleanup()
    elif args.peer:live(args.peer)
    else:parser.error("live requires --peer (test-phone public IPv4)")
