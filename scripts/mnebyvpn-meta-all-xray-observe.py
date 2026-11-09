#!/usr/bin/env python3
"""Operator-attested, read-only MNEBYVPN Xray socket observation for Meta Instagram/Threads.

No packet payload capture, Xray reconfiguration, browser account data or
credentials. No raw subscriber/source/destination IP address is printed.
Destination hostnames are only DNS co-location CANDIDATES, not proven TLS SNI.
All connections are aggregated; exclusive operator use must be attested before capture.
No file on remote VPS is created by this collector.\nDo not infer the user or application from these shared-process endpoints.
"""
from __future__ import annotations

import collections
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time

CONF = None  # This observer only uses the existing xray.service runtime, not config
STATE = None  # Subscriber state deliberately not inspected
SERVICE = "xray.service"
EXPECTED_BIN = pathlib.Path("/opt/xray/xray")
PROC = pathlib.Path("/proc")
META_HOSTS = (
    "instagram.com", "www.instagram.com", "i.instagram.com",
    "graph.instagram.com", "api.instagram.com",
    "cdninstagram.com", "scontent.cdninstagram.com",
    "edge-mqtt.facebook.com", "mqtt-ig-p4.facebook.com",
    "graph.facebook.com", "b-graph.facebook.com",
    "connect.facebook.net", "rupload.facebook.com",
    "static.xx.fbcdn.net", "www.facebook.com",
    "threads.com", "www.threads.com", "threads.net",
    "www.threads.net", "graph.threads.net",
    "meta.com", "meta.ai", "ig.me", "instagr.am",
    "instagramstatic-a.akamaihd.net",
)
META_ADDITIONAL_HOSTS = ()

def private_ip(addr: str) -> bool:
    obj = ipaddress.ip_address(addr)
    return not obj.is_global

def decode_endpoint(field: str, family: int) -> tuple[str, int]:
    addr, port = field.split(":")
    b = bytes.fromhex(addr)
    if family == socket.AF_INET:
        ip = socket.inet_ntop(family, b[::-1])
    else:
        if len(b) != 16:
            raise ValueError("Bad IPv6 proc table")
        ip = socket.inet_ntop(family, b"".join(b[i:i+4][::-1] for i in range(0,16,4)))
    return ip, int(port, 16)

def socket_inodes(pid: int, root: pathlib.Path = PROC) -> set[str]:
    fd = root / str(pid) / "fd"
    inodes: set[str] = set()
    for entry in fd.iterdir():
        try:
            link = os.readlink(entry)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[([0-9]+)\]", link)
        if match:
            inodes.add(match.group(1))
    return inodes

def active_vpn_ingress_count(pid: int, root: pathlib.Path = PROC) -> int:
    """Count established socket sessions owned by dedicated Xray inbound.

    A single established tunnel is a *correlation gate*, NOT cryptographic
    verification of which subscriber owns the connection.
    """
    owned = socket_inodes(pid, root)
    found: set[str] = set()
    for name, family in (("tcp",socket.AF_INET),("tcp6",socket.AF_INET6)):
        try:
            lines = (root/"net"/name).read_text().splitlines()[1:]
        except (FileNotFoundError, PermissionError):
            continue
        for line in lines:
            parts=line.split()
            if len(parts)<10 or parts[9] not in owned or parts[3]!="01":
                continue
            try:
                _local, port=decode_endpoint(parts[1],family)
                if port in (443,2053,8443,18943):
                    found.add(parts[9])
            except (ValueError,IndexError):
                continue
    return len(found)

def proc_sockets(pid: int, root: pathlib.Path = PROC) -> set[tuple[str, str, int]]:
    """Return only current global outgoing endpoints owned by Xray child."""
    inodes = socket_inodes(pid, root)
    if not inodes:
        return set()
    out = set()
    for name, family, proto in (
        ("tcp", socket.AF_INET, "tcp"), ("tcp6", socket.AF_INET6, "tcp"),
        ("udp", socket.AF_INET, "udp"), ("udp6", socket.AF_INET6, "udp"),
    ):
        try:
            rows = (root / "net" / name).read_text().splitlines()[1:]
        except (FileNotFoundError, PermissionError):
            continue
        for line in rows:
            parts = line.split()
            if len(parts) < 10 or parts[9] not in inodes:
                continue
            try:
                addr, port = decode_endpoint(parts[2], family)
                _source, localport = decode_endpoint(parts[1], family)
                if localport in (443,2053,8443,18943):
                    continue  # exclude inbound subscriber sockets, never attribute subscriber IPs
                if port == 0 or private_ip(addr):
                    continue
                # For TCP do not report transient not-yet-connected sockets.
                if proto == "tcp" and parts[3] != "01":
                    continue
                out.add((proto, addr, port))
            except (ValueError, IndexError):
                continue
    return out

def live_xray_pids() -> tuple[int, ...]:
    """Discover only executable xray workers. Do not inspect user credentials."""
    pids = []
    for entry in PROC.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if (entry / "comm").read_text().strip() != "xray":
                continue
            if (entry / "exe").resolve(strict=True).name != "xray":
                continue
            pids.append(int(entry.name))
        except (OSError, ValueError):
            continue
    result = tuple(sorted(pids))
    if not 1 <= len(result) <= 4:
        raise RuntimeError("Unexpected Xray process count")
    return result


def policy_preflight(exclusive_operator_test: bool = False) -> tuple[tuple[int,...], int, int]:
    if not exclusive_operator_test:
        raise RuntimeError("Explicit owner confirmation required")
    pids = live_xray_pids()
    sockets = set()
    for pid in pids:
        sockets.update(proc_sockets(pid))
    if not sockets:
        raise RuntimeError("No observable outbound Xray sockets")
    return pids, len(pids), len(sockets)

def hostname_candidates() -> dict[str, set[str]]:
    def resolve(host: str) -> tuple[str, set[str]]:
        try:
            addresses = {
                item[4][0] for item in socket.getaddrinfo(
                    host, 443, type=socket.SOCK_STREAM,
                ) if ipaddress.ip_address(item[4][0]).is_global
            }
            return host, addresses
        except (OSError, ValueError):
            return host, set()
    names = META_HOSTS + META_ADDITIONAL_HOSTS
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(resolve, name) for name in names]
        # Executor pool join is bounded by the OS resolver's existing behavior.
        return dict(f.result() for f in futures)

def summarize(observed: set[tuple[str,str,int]],
              mapping: dict[str,set[str]]) -> list[str]:
    # IP co-location is weak evidence because CDNs and Meta endpoints share IPs.
    ip_to_names: dict[str, set[str]] = collections.defaultdict(set)
    for host, addresses in mapping.items():
        for addr in addresses:
            ip_to_names[addr].add(host)
    candidate_ports: dict[str, set[str]] = collections.defaultdict(set)
    ports = collections.Counter()
    match_endpoints = 0
    for proto, dest, port in observed:
        ports[f"{proto}/{port}"] += 1
        names = ip_to_names.get(dest, ())
        if names:
            match_endpoints += 1
            for name in names:
                candidate_ports[name].add(f"{proto}/{port}")
    output = [
        "new_or_existing_global_remote_socket_endpoints=" + str(len(observed)),
        "endpoints_matching_current_Meta_DNS_A_AAAA=" + str(match_endpoints),
        "endpoints_with_no_current_Meta_DNS_match=" + str(len(observed)-match_endpoints),
        "ports=" + ",".join(f"{name}:{count}" for name,count in sorted(ports.items())),
    ]
    for host, protoports in sorted(candidate_ports.items()):
        # Only documented Meta-owned candidates; no personally identifying IPs.
        output.append(f"possible_Meta_destination={host} ports={','.join(sorted(protoports))}")
    output.extend([
        "domain_match_confidence=LOW_SHARED_IP_AND_DYNAMIC_DNS",
        "Meta_domain_on_each_connection_proven=false",
        "HTTPS_voice_content_decrypted=false",
        "raw_addresses_or_user_identifiers_logged=false",
        "DNS_only_non443_compatibility=UNVERIFIED",
    ])
    return output

def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("preflight","capture-exclusive"):
        raise SystemExit("Usage: script.py preflight|capture-exclusive")
    print("read_only_vpn_Meta_Instagram_Threads_all_Xray_processes_probe=true", flush=True)
    print("probe_mode=" + sys.argv[1], flush=True)
    try:
        pid, count, inbound_at_start = policy_preflight(
            exclusive_operator_test=sys.argv[1] == "capture-exclusive")
    except Exception as ex:
        # Don't print values from runtime configuration, identifiers or OS.
        print("preflight_status=NOT_READY", flush=True)
        print("reason=" + ("active_tunnels_not_unique" if "inbound tunnel" in str(ex)
              else "node_runtime_or_policy_mismatch"), flush=True)
        if "inbound tunnel count=" in str(ex):
            print("established_ingress_tunnels="+str(ex).rsplit("=",1)[1],flush=True)
        if sys.argv[1] == "preflight":
            print("preflight_report_only_no_changes=true",flush=True)
            return
        raise SystemExit(2)
    print("preflight_status=" + ("READY_OPERATOR_ATTESTED_EXCLUSIVE_WINDOW"
          if sys.argv[1] == "capture-exclusive" else "READY_SINGLE_ESTABLISHED_TUNNEL"),
          flush=True)
    print("xray_workers_observed="+str(count), flush=True)
    print("active_entitlement_count=NOT_INSPECTED_SHARED_XRAY", flush=True)
    print("outbound_endpoints_at_preflight=" + str(inbound_at_start), flush=True)
    print("per_credential_identity_attribution=NOT_VERIFIED", flush=True)
    print("capture_cannot_prove_client_app_or_exact_website=yes", flush=True)
    if sys.argv[1] == "preflight":
        return
    print("operator_exclusive_attribution=DECLARED_NOT_TECHNICALLY_PROVEN",flush=True)
    print("capture_may_include_other_apps_or_subscribers=YES",flush=True)
    # Baseline then explicit interaction window: only DIFFERENT destination
    # sockets go into the new-connection summary. Reused existing Meta
    # connections cannot be separated, so the full-window count is also given.
    mapping = hostname_candidates()
    print("capture_setup_complete_UTC=" +
          dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), flush=True)

    def sample_window(seconds: int) -> set[tuple[str,str,int]]:
        out: set[tuple[str,str,int]] = set()
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if live_xray_pids() != pid:
                print("capture_aborted_xray_process_changed=true", flush=True)
                raise SystemExit(3)
            try:
                for worker_pid in pid:
                    out.update(proc_sockets(worker_pid))
            except (OSError, PermissionError):
                print("capture_aborted_socket_visibility_changed=true", flush=True)
                raise SystemExit(3)
            time.sleep(.35)
        return out

    print("baseline_idle_window_seconds=15", flush=True)
    baseline=sample_window(15)
    print("META_TEST_WINDOW_OPEN_UTC=" +
          dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),flush=True)
    print("META_TEST_WINDOW_SECONDS=90", flush=True)
    interaction=sample_window(90)
    print("META_TEST_WINDOW_CLOSED_UTC=" +
          dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),flush=True)
    print("baseline_destination_count="+str(len(baseline)),flush=True)
    print("test_window_all_destination_count="+str(len(interaction)),flush=True)
    print("test_window_new_destination_count="+str(len(interaction-baseline)),flush=True)
    for line in summarize(interaction-baseline, mapping):
        print(line, flush=True)
    print("test_existing_connections_not_attributable=true", flush=True)
    print("capture_stopped_no_persistent_tracking=true", flush=True)

if __name__ == "__main__":
    main()
