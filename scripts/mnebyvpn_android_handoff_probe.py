#!/usr/bin/env python3
"""Android/Termux read-only diagnostic during Wi-Fi/VPN/Private DNS handoff.

Never changes Android settings or VPN. Writes only coarse status and errors to
a local JSONL file; no SSIDs, public IPs, personal DNS hostnames or credentials.
Run while switching networks/VPN. Result is only from this phone, unlike CI.
"""
import argparse
import collections
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time

from mnebyvpn_dns_vpn_handoff_monitor import frame, check_dns, classify_error

IP = "89.125.90.101"


def command(args, timeout=3):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def private_dns_name():
    name = os.environ.get("MNEBYVPN_PRIVATE_DNS_HOST", "").strip()
    if not name:
        name = (command(["settings", "get", "global", "private_dns_specifier"]) or "").strip()
    if not re.fullmatch(r"[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.dns\.mnebyvpn\.site|dns\.mnebyvpn\.site", name):
        return None
    return name


def system_dns():
    start = time.monotonic()
    try:
        # Android's libc resolver can block beyond socket.timeout. A short-lived
        # subprocess provides a hard deadline while avoiding orphaned threads.
        # Results may be cached, so this is not proof of live DNS reachability.
        check = ("import socket,sys;"
                 "v=socket.getaddrinfo('example.org',443,"
                 "family=socket.AF_INET,type=socket.SOCK_STREAM);"
                 "sys.exit(0 if v else 1)")
        run = subprocess.run([sys.executable, "-c", check], timeout=5,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if run.returncode:
            raise OSError("resolver_failed")
        return {"ok": True, "ms": round((time.monotonic() - start) * 1000)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout",
                "ms": round((time.monotonic() - start) * 1000)}
    except (OSError, TimeoutError) as ex:
        return {"ok": False, "error": classify_error(ex),
                "ms": round((time.monotonic() - start) * 1000)}


def actual_personal_dot(host):
    if not host:
        return {"ok": None, "reason": "personal_host_unavailable"}
    start = time.monotonic()
    phase = "tcp"
    try:
        with socket.create_connection((IP, 853), timeout=3.5) as sock:
            sock.settimeout(3.5)
            phase = "tls"
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                tls.settimeout(3.5)
                phase = "dns"
                txid = int.from_bytes(os.urandom(2), "big")
                wire, question = frame(txid)
                tls.sendall(wire)
                check_dns(tls, txid, question)
        return {"ok": True, "phase": "done", "ms": round((time.monotonic() - start) * 1000)}
    except (OSError, EOFError, ValueError) as ex:
        return {"ok": False, "phase": phase, "error": classify_error(ex),
                "ms": round((time.monotonic() - start) * 1000)}


def wifi_hint(session_key=None):
    """Return Wi-Fi state and optional *memory-only* network identity.

    Identity is HMAC-keyed per run; it is never logged, printed or persisted.
    This detects Wi-Fi A -> Wi-Fi B while the connected flag stays True.
    """
    raw = command(["termux-wifi-connectioninfo"], timeout=2)
    unavailable = (None, None) if session_key is not None else None
    if not raw:
        return unavailable
    try:
        data = json.loads(raw)
        state = str(data.get("supplicant_state", "")).upper()
        if state in ("COMPLETED", "CONNECTED"):
            connected = True
        elif state in ("DISCONNECTED", "INACTIVE", "SCANNING"):
            connected = False
        else:
            return unavailable
        if session_key is None:
            return connected
        raw_identity = ""
        for field in ("bssid", "ssid"):
            candidate = data.get(field, "")
            if (isinstance(candidate, str) and candidate
                    and candidate.lower() not in (
                        "02:00:00:00:00:00", "<unknown ssid>", "unknown",
                        "00:00:00:00:00:00")):
                raw_identity = candidate
                break
        token = (hmac.new(session_key, raw_identity.encode("utf8"),
                          hashlib.sha256).digest()
                 if connected and raw_identity else None)
        return connected, token
    except (TypeError, ValueError):
        return unavailable

def mode_hint():
    raw = command(["settings", "get", "global", "private_dns_mode"])
    return raw if raw in ("hostname", "off", "opportunistic") else "unknown"


def classification(os_result, dot_result):
    system_fail = os_result["ok"] is False
    # Unknown personal DoT must never be treated as a successful DoT probe.
    if dot_result["ok"] is None:
        return ("system_resolver_failed_dot_unverified" if system_fail
                else "personal_dot_not_tested")
    if system_fail and dot_result["ok"] is False:
        return "system_dns_and_dot_failed"
    if system_fail:
        return "system_resolver_problem"
    if dot_result["ok"] is False:
        return "private_dot_path_problem"
    return "healthy_observed"


def next_transition(incident, fail_streak, state, wifi_changed=False):
    """Keep distinct network and incident events without false recovery."""
    failures = {
        "system_dns_and_dot_failed", "system_resolver_problem",
        "private_dot_path_problem", "system_resolver_failed_dot_unverified",
    }
    events = ["wifi_hint_changed"] if wifi_changed else []
    if state in failures:
        fail_streak += 1
        if fail_streak >= 2 and not incident:
            events.append("incident_started")
            incident = True
    elif state == "healthy_observed":
        fail_streak = 0
        if incident:
            events.append("incident_recovered")
            incident = False
    else:
        # No usable personal DoT sample is not a successful recovery.
        fail_streak = 0
    return events, incident, fail_streak


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--output", default="mnebyvpn-handoff-local.jsonl")
    args = parser.parse_args()
    if not 10 <= args.seconds <= 900 or not 1 <= args.interval <= 30:
        parser.error("duration must be 10..900s, interval 1..30s")
    host = private_dns_name()
    previous_wifi = None
    previous_network_token = None
    ephemeral_network_key = secrets.token_bytes(32)
    incident = False
    fail_streak = 0
    counts = collections.Counter()
    started = time.monotonic()
    limit = started + args.seconds
    print("PERSONAL_DOT_CONFIGURED=" + str(host is not None).lower(), flush=True)
    print("CLIENT_MONITOR=LOCAL_ONLY_NO_WIFI_SSID_NO_IP_NO_SECRET", flush=True)
    print("SWITCH_WIFI_AND_VPN_DURING_TEST=true", flush=True)
    with open(args.output, "w", encoding="utf8") as log:
        while time.monotonic() < limit:
            stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            wifi, network_token = wifi_hint(ephemeral_network_key)
            os_result = system_dns()
            dot_result = actual_personal_dot(host)
            state = classification(os_result, dot_result)
            counts[state] += 1
            wifi_changed = (
                previous_wifi is not None and wifi is not None
                and (wifi != previous_wifi
                     or (wifi and previous_network_token is not None
                         and network_token is not None
                         and network_token != previous_network_token)))
            events, incident, fail_streak = next_transition(
                incident, fail_streak, state, wifi_changed=wifi_changed)
            if wifi is not None:
                previous_wifi = wifi
            if wifi is False:
                previous_network_token = None
            elif network_token is not None:
                previous_network_token = network_token
            item = {"at_utc": stamp, "events": events, "state": state,
                    "system_dns": os_result, "personal_dot": dot_result,
                    "wifi_connected_hint": wifi, "android_private_dns_mode": mode_hint(),
                    "vpn_enabled_verified": False}
            log.write(json.dumps(item, separators=(",", ":")) + "\n")
            log.flush()
            for event in events:
                print(stamp + " " + event + " " + state, flush=True)
            time.sleep(min(args.interval, max(0.0, limit - time.monotonic())))
    print("CLIENT_MONITOR_COUNTS="+json.dumps(dict(counts),sort_keys=True),flush=True)
    print("CLIENT_MONITOR_LOG="+args.output,flush=True)


if __name__ == "__main__":
    main()
