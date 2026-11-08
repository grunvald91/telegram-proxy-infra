#!/usr/bin/env python3
"""Single-client, read-only MNEBYVPN Xray socket observation for Gemini tests.

No packet payload capture, Xray reconfiguration, browser account data or
credentials. No raw subscriber/source/destination IP address is printed.
Destination hostnames are only DNS co-location CANDIDATES, not proven TLS SNI.
Abort immediately if zero or multiple simultaneously enabled VPN accounts.
No file on remote VPS is created by this collector.
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

CONF = pathlib.Path("/etc/mnebyvpn/xray-canary.json")
STATE = pathlib.Path("/var/lib/mnebyvpn-vpn/state.json")
SERVICE = "mnebyvpn-vpn-provisioner.service"
EXPECTED_BIN = pathlib.Path("/opt/xray/xray")
PROC = pathlib.Path("/proc")
GEMINI_HOSTS = (
    # Google official Gemini App firewall host inventory, as of 2026-11-08
    # https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/gemini-app-firewall-settings
    "lh5.googleusercontent.com", "www.googleapis.com", "ssl.gstatic.com",
    "fonts.googleapis.com", "play.google.com", "ogs.google.com",
    "www.google.com", "apis.google.com", "jnn-pa.googleapis.com",
    "waa-pa.clients6.google.com", "i.ytimg.com", "yt3.ggpht.com",
    "lh3.googleusercontent.com", "maps.gstatic.com", "lh3.google.com",
    "ogads-pa.clients6.google.com", "csp.withgoogle.com",
    "www.googletagmanager.com", "www.youtube.com",
    "fonts.gstatic.com", "maps.googleapis.com", "static.doubleclick.net",
    "www.gstatic.com", "gemini.google.com", "td.doubleclick.net",
    "googleads.g.doubleclick.net", "www.google-analytics.com",
    "optimizationguide-pa.googleapis.com",
    "encrypted-tbn0.gstatic.com", "encrypted-tbn1.gstatic.com",
    "encrypted-tbn2.gstatic.com", "encrypted-tbn3.gstatic.com",
    "streetviewpixels-pa.googleapis.com", "content-autofill.googleapis.com",
)
ANDROID_SYSTEM_HOSTS = (
    "mtalk.google.com", "mtalk4.google.com", "time.google.com",
    "fcm.googleapis.com", "firebaseinstallations.googleapis.com",
    "gcm-http.googleapis.com", "gcm-xmpp.googleapis.com",
    "android.googleapis.com", "pki.google.com", "clients1.google.com",
    "notifications.google.com",
)

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
                if port in (18943,2053):
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
                if port == 0 or private_ip(addr):
                    continue
                # For TCP do not report transient not-yet-connected sockets.
                if proto == "tcp" and parts[3] != "01":
                    continue
                out.add((proto, addr, port))
            except (ValueError, IndexError):
                continue
    return out

def active_count(now: dt.datetime | None = None) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    data = json.loads(STATE.read_text())
    if not isinstance(data, dict):
        raise ValueError("Unexpected VPN state")
    count = 0
    for entry in data.values():
        if entry.get("enabled") is not True:
            continue
        expiry = dt.datetime.fromisoformat(entry["expiresAt"].replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            raise ValueError("Missing timezone in account expiry")
        if expiry > now:
            count += 1
    return count

def isolated_child_pid() -> int:
    r = subprocess.run(
        ["systemctl", "show", "-p", "MainPID", "--value", SERVICE],
        text=True, capture_output=True, check=True, timeout=8,
    )
    parent = int(r.stdout.strip())
    if parent <= 1:
        raise RuntimeError("VPN agent not active")
    # No restarting the live Xray process or consulting logs.
    children = (PROC / str(parent) / "task" / str(parent) / "children").read_text().split()
    found = []
    for child in children:
        pid = int(child)
        try:
            executable = (PROC / str(pid) / "exe").resolve(strict=True)
            command = (PROC / str(pid) / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if executable == EXPECTED_BIN.resolve(strict=True) and (
            b"/etc/mnebyvpn/xray-canary.json" in command
        ):
            found.append(pid)
    if len(found) != 1:
        raise RuntimeError("Isolated Xray child not unique")
    return found[0]

def policy_preflight(exclusive_operator_test: bool = False) -> tuple[int, int, int]:
    data = json.loads(CONF.read_text())
    ins = data.get("inbounds", [])
    if not isinstance(ins, list) or len(ins) not in (1, 2):
        raise RuntimeError("Unexpected Xray topology")
    main = ins[0]
    if (main.get("tag") != "mnebyvpn-inbound"
            or main.get("listen") != "127.0.0.1"
            or main.get("port") != 18943
            or main.get("protocol") != "vless"):
        raise RuntimeError("Unknown Xray config")
    clients = main.get("settings", {}).get("clients", [])
    count = active_count()
    if count < 1 or len(clients) != count:
        raise RuntimeError("Out-of-sync Xray and active entitlement counts")
    if data.get("log", {}).get("loglevel") not in ("warning", "error", "none"):
        raise RuntimeError("Unexpected verbose Xray config")
    if data.get("log", {}).get("access", "none") not in ("none", "", None):
        raise RuntimeError("Unexpected Xray access logging")
    pid = isolated_child_pid()
    tunnel_count = active_vpn_ingress_count(pid)
    # Multiple concurrent tunnels are normal for a single proxy app. Their
    # owner cannot be inferred from /proc. Manual exclusive operator attestation
    # allows ONLY a bounded test window, and is NOT true per-user telemetry.
    if not (1 <= tunnel_count <= 128):
        raise RuntimeError("Unusual established Xray inbound tunnel count="+str(tunnel_count))
    if not exclusive_operator_test and tunnel_count != 1:
        raise RuntimeError("Require exactly one established Xray inbound tunnel count="+str(tunnel_count))
    return pid, count, tunnel_count

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
    names = GEMINI_HOSTS + ANDROID_SYSTEM_HOSTS
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(resolve, name) for name in names]
        # Executor pool join is bounded by the OS resolver's existing behavior.
        return dict(f.result() for f in futures)

def summarize(observed: set[tuple[str,str,int]],
              mapping: dict[str,set[str]]) -> list[str]:
    # IP co-location is weak evidence because CDNs and Google endpoints share IPs.
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
        "endpoints_matching_current_Google_DNS_A_AAAA=" + str(match_endpoints),
        "endpoints_with_no_current_Google_DNS_match=" + str(len(observed)-match_endpoints),
        "ports=" + ",".join(f"{name}:{count}" for name,count in sorted(ports.items())),
    ]
    for host, protoports in sorted(candidate_ports.items()):
        # Only documented Google-owned candidates; no personally identifying IPs.
        output.append(f"possible_Google_destination={host} ports={','.join(sorted(protoports))}")
    output.extend([
        "domain_match_confidence=LOW_SHARED_IP_AND_DYNAMIC_DNS",
        "Google_domain_on_each_connection_proven=false",
        "HTTPS_voice_content_decrypted=false",
        "raw_addresses_or_user_identifiers_logged=false",
        "DNS_only_non443_compatibility=UNVERIFIED",
    ])
    return output

def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("preflight","capture-exclusive"):
        raise SystemExit("Usage: script.py preflight|capture-exclusive")
    print("read_only_vpn_Gemini_probe=true", flush=True)
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
    print("outbound_pid_present=true", flush=True)
    print("active_entitlement_count=" + str(count), flush=True)
    print("established_ingress_tunnels=" + str(inbound_at_start), flush=True)
    print("per_credential_identity_attribution=NOT_VERIFIED", flush=True)
    print("capture_cannot_prove_process_or_exact_website=yes", flush=True)
    if sys.argv[1] == "preflight":
        return
    print("operator_exclusive_attribution=DECLARED_NOT_TECHNICALLY_PROVEN",flush=True)
    print("capture_may_include_other_apps_or_subscribers=YES",flush=True)
    # Baseline then explicit interaction window: only DIFFERENT destination
    # sockets go into the new-connection summary. Reused existing Google
    # connections cannot be separated, so the full-window count is also given.
    mapping = hostname_candidates()
    print("capture_setup_complete_UTC=" +
          dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), flush=True)

    def sample_window(seconds: int) -> set[tuple[str,str,int]]:
        out: set[tuple[str,str,int]] = set()
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if (active_count() != count or isolated_child_pid() != pid
                or not (1 <= active_vpn_ingress_count(pid) <= 128)):
                print("capture_aborted_account_or_process_changed=true", flush=True)
                raise SystemExit(3)
            try:
                out.update(proc_sockets(pid))
            except (OSError, PermissionError):
                print("capture_aborted_socket_visibility_changed=true", flush=True)
                raise SystemExit(3)
            time.sleep(.35)
        return out

    print("baseline_idle_window_seconds=15", flush=True)
    baseline=sample_window(15)
    print("GEMINI_TEST_WINDOW_OPEN_UTC=" +
          dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),flush=True)
    print("GEMINI_TEST_WINDOW_SECONDS=90", flush=True)
    interaction=sample_window(90)
    print("GEMINI_TEST_WINDOW_CLOSED_UTC=" +
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
