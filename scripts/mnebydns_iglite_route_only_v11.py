#!/usr/bin/env python3
"""One-shot v11 Meta exact-host ROUTE-ONLY 900s diagnostic on DE.

Does NOT disable TCP window scaling, add nftables rules, or change TCP
packet windows. The previous global-window20 v10 trial affected non-Meta
HTTPS; v11 must never reproduce it. Nginx/CoreDNS are changed only by
reversible exact-host Meta entries, with independent same-boot rollback.
TLS SNI capture is in memory and prints aggregate counters only.
This is a diagnostic, NOT a proven DPI bypass or a proof of phone identity.
"""
from __future__ import annotations
import os
from pathlib import Path
import signal
import sys
import time

import mnebydns_iglite_wifi_multi_meta_v10_w20 as base

base.ROOT = Path("/var/lib/mneby-iglite-wifi-de-20261111-v11")
base.UNIT = "mneby-ig-lite-route-only-20261111-v11"
base.TABLE = "mneby_ig_lite_route_only_20261111_v11"
base.PERSISTENT_STAGE = Path("/usr/local/libexec/mneby-iglite-v11")

def live():
    if os.environ.get("MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED") != "YES":
        raise RuntimeError("Owner must explicitly approve route-only v11")
    original_nginx,original_core=base.baseline()
    if base.WSFILE.read_text().strip()!="1":
        raise RuntimeError("Refuse v11 if normal TCP scaling is disabled")
    m=base.owner()
    ng,core=original_nginx.decode(),original_core.decode()
    accepted=[]
    for hostname in base.HOSTS:
        origin=m.origin_ip(hostname)
        ng=m.nginx_add(ng,hostname,origin)
        core=m.core_add(core,hostname)
        accepted.append(hostname)
        print("iglite_v11_exact_host_routed="+hostname,flush=True)
    reverse_ng,reverse_core=ng,core
    for hostname in reversed(accepted):
        reverse_ng=m.nginx_remove(reverse_ng,hostname)
        reverse_core=m.core_remove(reverse_core,hostname)
    if reverse_ng.encode()!=original_nginx or reverse_core.encode()!=original_core:
        raise RuntimeError("v11 exact route edits must be byte-reversible")
    print("iglite_v11_exact_host_count="+str(len(accepted)),flush=True)
    if len(accepted)!=len(base.HOSTS):
        raise RuntimeError("v11 incomplete Meta coverage")
    if base.command(["nft","list","table","inet",base.TABLE],check=False).returncode==0:
        raise RuntimeError("Unexpected v11 packet-mangling nft table")
    root=base.ROOT
    root.mkdir(parents=True,mode=0o700,exist_ok=False)
    base.write_exclusive(root/"tcp_window_scaling.original",base.WSFILE.read_bytes())
    base.write_exclusive(root/"nginx.original",original_nginx)
    base.write_exclusive(root/"core.original",original_core)
    base.write_exclusive(root/"nginx.candidate",ng.encode())
    base.write_exclusive(root/"core.candidate",core.encode())
    base.fsync_directory(root)
    base.fsync_directory(root.parent)
    base.command(["nginx","-t","-c",str(root/"nginx.candidate")])
    watchdog_start=time.monotonic()
    base.command(["systemd-run","--quiet","--collect","--unit",base.UNIT,
                  "--on-active="+str(base.WATCHDOG_SECONDS)+"s",
                  "/usr/bin/python3",str(Path(__file__).resolve()),"rollback"])
    if base.command(["systemctl","is-active","--quiet",base.UNIT+".timer"],
                    check=False).returncode!=0:
        raise RuntimeError("Independent v11 same-boot rollback timer not armed")
    print("iglite_v11_same_boot_watchdog_armed=true",flush=True)
    base.write_exclusive(root/base.MUTATION_MARKER,b"armed\n")
    base.fsync_directory(root)
    try:
        # No sysctl or nft mutations are allowed anywhere in the v11 live path.
        base.atomic_replace(base.NGINX,ng.encode())
        base.command(["nginx","-t"],timeout=20)
        base.command(["systemctl","reload","nginx.service"],timeout=20)
        base.atomic_replace(base.CORE,core.encode())
        base.command(["systemctl","restart","mnebydns-dot.service"],timeout=30)
        from mnebydns_iglite_dns_wire_checks import check_exact_types
        for hostname in accepted:
            for attempt in range(21):
                try:
                    kinds=check_exact_types(host=hostname)
                    break
                except (ConnectionRefusedError,ConnectionResetError,TimeoutError):
                    if attempt==20:raise
                    time.sleep(.5)
            if any(value not in ("A_EXACT_DE","NO_ALIAS_OR_IPV6") for value in kinds.values()):
                raise RuntimeError("DNS wire A/AAAA/HTTPS/CNAME escaped exact DE route")
            print("iglite_v11_dns_exact_verified="+hostname,flush=True)
        print("iglite_v11_tls="+base.live_tls(),flush=True)
        if base.WSFILE.read_text().strip()!="1":
            raise RuntimeError("Unexpected global TCP scaling change")
        if base.command(["nft","list","table","inet",base.TABLE],check=False).returncode==0:
            raise RuntimeError("Unexpected v11 nft table during diagnostic")
        from mnebydns_iglite_sni_observer import begin,finish,summary
        pcap,thread,analyzer,errors=begin(base.HOSTS)
        if pcap.poll() is not None:
            raise RuntimeError("SNI observer unexpectedly stopped")
        remaining=base.WATCHDOG_SECONDS-(time.monotonic()-watchdog_start)
        if remaining<base.TRIAL_SECONDS+base.MIN_ROLLBACK_MARGIN:
            finish(pcap,thread,analyzer,errors)
            raise RuntimeError("Insufficient rollback margin before the 900s capture")
        print("iglite_v11_transport=ROUTE_ONLY_NO_SYSCTL_NO_NFT",flush=True)
        start=int(time.time())
        base.write_exclusive(root/"ready_epoch",str(start).encode("ascii"))
        print("iglite_v11_capture_start_epoch_s="+str(start),flush=True)
        print("iglite_v11_15min_window=READY",flush=True)
        try:
            time.sleep(base.TRIAL_SECONDS)
        finally:
            summary(finish(pcap,thread,analyzer,errors))
        if base.WSFILE.read_text().strip()!="1":
            raise RuntimeError("TCP scaling changed unexpectedly")
    finally:
        base.rollback()
    print("iglite_v11_end_to_end_android=NOT_PROVEN",flush=True)

if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("live","rollback"):
        raise SystemExit("Usage: route_only_v11.py live|rollback")
    if sys.argv[1]=="rollback":
        base.rollback()
    else:
        live()
