#!/usr/bin/env python3
"""Android/Termux read-only diagnostic during Wi-Fi/VPN/Private DNS handoff.

Never changes Android settings or VPN. Writes only coarse status and errors to
a local JSONL file; no SSIDs, public IPs, personal DNS hostnames or credentials.
Run while switching networks/VPN. Result is only from this phone, unlike CI.
"""
import argparse
import collections
import datetime as dt
import json
import os
import re
import socket
import ssl
import struct
import subprocess
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
        # This can be cached by Android; it complements, never replaces, DoT.
        answers = socket.getaddrinfo("example.org", 443, family=socket.AF_INET,
                                     type=socket.SOCK_STREAM)
        if not answers:
            raise OSError("empty resolver result")
        return {"ok": True, "ms": round((time.monotonic() - start) * 1000)}
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


def wifi_hint():
    # Optional Termux:API. Never save SSID, BSSID, local IP, MAC or gateway.
    raw = command(["termux-wifi-connectioninfo"], timeout=2)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        state = str(data.get("supplicant_state", "")).upper()
        if state in ("COMPLETED", "CONNECTED"):
            return True
        if state in ("DISCONNECTED", "INACTIVE", "SCANNING"):
            return False
    except (TypeError, ValueError):
        pass
    return None


def mode_hint():
    raw = command(["settings", "get", "global", "private_dns_mode"])
    return raw if raw in ("hostname", "off", "opportunistic") else "unknown"


def classification(os_result, dot_result):
    system_fail = os_result["ok"] is False
    dot_fail = dot_result["ok"] is False
    if system_fail and dot_fail:
        return "system_dns_and_dot_failed"
    if system_fail and not dot_fail:
        return "system_resolver_problem"
    if dot_fail and not system_fail:
        return "private_dot_path_problem"
    if dot_result["ok"] is None:
        return "personal_dot_not_tested"
    return "healthy_observed"


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
            wifi = wifi_hint()
            os_result = system_dns()
            dot_result = actual_personal_dot(host)
            state = classification(os_result, dot_result)
            counts[state] += 1
            failing = state in ("system_dns_and_dot_failed",
                                "system_resolver_problem", "private_dot_path_problem")
            fail_streak = fail_streak + 1 if failing else 0
            event = "sample"
            if previous_wifi is not None and wifi is not None and wifi != previous_wifi:
                event = "wifi_hint_changed"
            if fail_streak >= 2 and not incident:
                event, incident = "incident_started", True
            if incident and not failing:
                event, incident = "incident_recovered", False
            if wifi is not None:
                previous_wifi = wifi
            item = {"at_utc": stamp, "event": event, "state": state,
                    "system_dns": os_result, "personal_dot": dot_result,
                    "wifi_connected_hint": wifi, "android_private_dns_mode": mode_hint(),
                    "vpn_enabled_verified": False}
            log.write(json.dumps(item, separators=(",", ":")) + "\n")
            log.flush()
            if event != "sample":
                print(stamp + " " + event + " " + state, flush=True)
            time.sleep(min(args.interval, max(0.0, limit - time.monotonic())))
    print("CLIENT_MONITOR_COUNTS="+json.dumps(dict(counts),sort_keys=True),flush=True)
    print("CLIENT_MONITOR_LOG="+args.output,flush=True)


if __name__ == "__main__":
    main()
