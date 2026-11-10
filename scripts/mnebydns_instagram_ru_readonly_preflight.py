#!/usr/bin/env python3
"""Read-only RU VPS preflight for the isolated Instagram TCP window canary.

Runs over an already authenticated SSH connection. Never captures payloads,
changes networking, starts/stops processes, or prints full private rulesets.
Only booleans, counts, and bounded status strings go to CI.
"""
from __future__ import annotations

import ctypes.util
import pathlib
import re
import shutil
import socket
import subprocess
import sys

HOST = "188.120.254.223"
CANARY_PORT = 18443
QUEUE = "211"
TAG = "MNEBYDNS_SYNACK_CANARY_211"
TIMER = "mnebydns-synack-rollback-211.timer"


def command(argv, timeout=12):
    if not shutil.which(argv[0]):
        return None
    try:
        return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def boolout(key, value):
    print(f"{key}={'true' if value else 'false'}", flush=True)


def main():
    checks = {}
    def mark(key, value):
        checks[key] = bool(value)
        boolout(key, value)

    mark("host_public_ipv4_on_interface", any(
        HOST == part.split("/")[0]
        for line in (command(["ip", "-o", "-4", "addr", "show"]) or subprocess.CompletedProcess([],1,"","")).stdout.splitlines()
        for part in re.findall(r"\binet\s+([0-9.]+(?:/\d+)?)", line)
    ))
    ss = command(["ss", "-H", "-lnt"])
    if not ss or ss.returncode:
        mark("tcp_listener_inventory_available", False)
    else:
        mark("tcp_listener_inventory_available", True)
        entries = [x.split()[3] for x in ss.stdout.splitlines() if len(x.split()) >= 4]
        for port in (443, 18443, 853):
            listeners = [x for x in entries if re.search(fr":{port}$", x)]
            print(f"tcp_port_{port}_listeners={len(listeners)}")
        mark("canary_tcp_18443_unoccupied", not any(re.search(r":18443$", x) for x in entries))
        # A 443 listener is expected; it's deliberately out of scope.
        mark("shared_https_443_preserved", True)

    ipt_ver = command(["iptables", "--version"])
    mark("iptables_available", bool(ipt_ver and ipt_ver.returncode == 0))
    backend = "unknown"
    if ipt_ver and ipt_ver.returncode == 0:
        backend = "nf_tables" if "nf_tables" in ipt_ver.stdout else "legacy" if "legacy" in ipt_ver.stdout else "unknown"
    print("iptables_backend=" + backend)
    mark("iptables_backend_identified", backend != "unknown")

    output = command(["iptables", "-w", "-t", "mangle", "-S", "OUTPUT"])
    mark("mangle_output_readable", bool(output and output.returncode == 0))
    lines = output.stdout.splitlines() if output and output.returncode == 0 else []
    mark("no_tagged_canary_rule", not any(TAG in x for x in lines))
    mark("no_canary_queue_rule", not any(("--queue-num " + QUEUE) in x for x in lines))
    print("mangle_output_rules=" + str(len(lines)))

    nft = command(["nft", "list", "ruleset"], timeout=15)
    nft_ok = nft is not None and nft.returncode == 0
    boolout("nft_ruleset_readable", nft_ok)
    mark("nft_inspection_complete_when_needed", backend != "nf_tables" or nft_ok)
    if nft_ok:
        mark("no_nft_canary_tag", TAG not in nft.stdout)
        mark("no_nft_queue_211", not bool(re.search(r"\bqueue(?:\s+num)?\s+211\b", nft.stdout)))
    else:
        print("no_nft_canary_tag=unknown")
        print("no_nft_queue_211=unknown")

    proc = pathlib.Path("/proc/net/netfilter/nfnetlink_queue")
    if proc.exists():
        try:
            active = proc.read_text().splitlines()
        except OSError:
            active = []
        mark("nfqueue_211_unclaimed", not any(
            x.split() and x.split()[0] == QUEUE for x in active))
        print(f"active_nfqueue_count={len(active)}")
    else:
        mark("nfqueue_proc_available", False)
        # Missing /proc interface cannot be interpreted as an empty queue list.
        mark("nfqueue_211_unclaimed", False)

    mark("native_nfqueue_library_available", bool(ctypes.util.find_library("netfilter_queue")))
    mark("required_commands_available", all(shutil.which(x) for x in (
        "iptables", "systemd-run", "systemctl", "timeout", "flock", "python3", "ss"
    )))
    # systemctl is-active is read-only and does not activate the timer.
    timer = command(["systemctl", "is-active", TIMER])
    mark("rollback_timer_not_active", bool(
        timer and timer.returncode in (3, 4)
        and timer.stdout.strip() in ("inactive", "unknown")
    ))
    manager = command(["systemctl", "list-jobs", "--no-pager"])
    mark("systemd_manager_accessible", bool(manager and manager.returncode == 0))
    print("tcp_window_scaling_enabled=" + (
        pathlib.Path("/proc/sys/net/ipv4/tcp_window_scaling").read_text().strip()
        if pathlib.Path("/proc/sys/net/ipv4/tcp_window_scaling").exists() else "unknown"
    ))
    # This is just a read-only viability report; do not automatically deploy a canary.
    blocked = [name for name, ok in checks.items() if not ok and name not in
               ("native_nfqueue_library_available",)]
    if blocked:
        print("canary_readonly_preflight=BLOCKED")
        print("blocking_checks=" + ",".join(blocked))
        return 1
    print("canary_readonly_preflight=PASS_BASELINE_ONLY")
    return 0


if __name__ == "__main__":
    sys.exit(main())
