#!/usr/bin/env python3
"""One-shot DE egress NFQUEUE210 exemption for one GitHub runner SSH peer.

The mark bit is already excluded by telegram_nfqws postrouting NFQUEUE rule.
This test DOES NOT change Telegram worker, DNS, nginx or other client flows.
Fail-safe deletion is armed via systemd before nft mutates any live rules.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time

DE = "89.125.90.101"
TABLE = "mneby_ig_q210_probe_20261111"
UNIT = "mneby-ig-q210-probe-20261111"
SKIP_QUEUE_MARK = "0x40000000"
DURATION_SECONDS = 24
WATCHDOG_SECONDS = 75


def run(args, *, source=None, check=True, timeout=12):
    p = subprocess.run(args, input=source, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(str(args[0]) + " exited " + str(p.returncode))
    return p


def nft_has_table():
    return run(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0


def audit_rule():
    result = run(["nft", "-j", "-a", "list", "ruleset"])
    items = json.loads(result.stdout).get("nftables", [])
    parent = [
        obj["chain"] for obj in items if "chain" in obj
        and obj["chain"].get("family") == "inet"
        and obj["chain"].get("table") == "telegram_nfqws"
        and obj["chain"].get("name") == "post"
        and obj["chain"].get("hook") == "postrouting"
    ]
    if len(parent) != 1:
        raise RuntimeError("Existing Telegram NFQUEUE postrouting chain not unique")
    priority = parent[0]["prio"]
    if isinstance(priority, str):
        priority = {"mangle": -150}.get(priority, priority)
    priority = int(priority)
    queue_rules = [
        obj["rule"] for obj in items if "rule" in obj
        and obj["rule"].get("family") == "inet"
        and obj["rule"].get("table") == "telegram_nfqws"
        and obj["rule"].get("chain") == "post"
        and any("queue" in expression and expression["queue"].get("num") == 210
                for expression in obj["rule"].get("expr", []))
    ]
    if len(queue_rules) != 1:
        raise RuntimeError("NFQUEUE210 server rule not pinned uniquely")
    expr = json.dumps(queue_rules[0]["expr"], separators=(",", ":"))
    if not all(token in expr for token in (
        '"sport"', '"right":443', '"key":"mark"', "1073741824",
        '"key":"packets"', '"dir":"reply"', '"num":210',
    )):
        raise RuntimeError("Unexpected telegram_nfqueue210 packet selection")
    return priority


def peer_ip():
    words = os.environ.get("SSH_CONNECTION", "").split()
    if len(words) != 4:
        raise RuntimeError("SSH_CONNECTION missing; cannot identify one test client")
    peer = ipaddress.ip_address(words[0])
    if peer.version != 4 or not peer.is_global or str(peer) == DE:
        raise RuntimeError("Expected distinct public IPv4 SSH peer")
    return str(peer)


def verify_prerequisites():
    if os.geteuid() != 0 or os.environ.get("MNEBY_NFQ210_ONCE_APPROVED") != "YES":
        raise RuntimeError("Root and owner-approved single-shot flag required")
    if not shutil.which("nft") or not os.path.isfile("/usr/sbin/nft"):
        raise RuntimeError("Pinned nft binary missing")
    if nft_has_table():
        raise RuntimeError("Experiment table already exists")
    if run(["systemctl", "is-active", "--quiet", UNIT + ".timer"],
           check=False).returncode == 0:
        raise RuntimeError("Prior cleanup timer still active")
    for svc in ("nginx.service", "mnebydns-dot.service"):
        if run(["systemctl", "is-active", "--quiet", svc], check=False).returncode:
            raise RuntimeError("Baseline service not active")
    expected = run(["ip", "-4", "-o", "addr", "show"]).stdout
    if not re.search(r"\s89[.]125[.]90[.]101/", expected):
        raise RuntimeError("Wrong server")


def main():
    verify_prerequisites()
    peer = peer_ip()
    p = audit_rule()
    # Precede the existing NFQUEUE postrouting hook by exactly one priority.
    # Only this SSH runner's DE:443 reply packets are marked to skip queue210.
    script = (
        "add table inet " + TABLE + "\n"
        "add chain inet " + TABLE + " post { type filter hook postrouting priority "
        + str(p - 1) + "; policy accept; }\n"
        "add rule inet " + TABLE + " post oifname \"eth0\""
        " ip saddr " + DE + " ip daddr " + peer
        + " tcp sport 443 counter meta mark set " + SKIP_QUEUE_MARK
        + " comment \"MNEBY_IG_PEER_QUEUE210_EXEMPTION\"\n"
    )
    run(["nft", "--check", "-f", "-"], source=script)
    print("de_nfq210_rule_pinned=true", flush=True)
    print("de_nfq210_rule_syntax=VALID", flush=True)
    # Do NOT cancel this independent timer; it remains armed even after
    # this process exits and completes a no-op on already-deleted tables.
    run(["systemd-run", "--quiet", "--collect", "--unit", UNIT,
         "--on-active=" + str(WATCHDOG_SECONDS) + "s",
         "/usr/bin/python3", "-c",
         ("import subprocess;subprocess.run("
          "['/usr/sbin/nft','delete','table','inet','" + TABLE + "'],"
          "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)")])
    if run(["systemctl", "is-active", "--quiet", UNIT + ".timer"],
           check=False).returncode != 0:
        raise RuntimeError("Independent rollback timer was not armed")
    print("de_nfq210_independent_rollback=ARMED", flush=True)
    try:
        run(["nft", "-f", "-"], source=script)
        if not nft_has_table():
            raise RuntimeError("Timed test table not active")
        print("de_nfq210_peer_bypass=ACTIVE", flush=True)
        time.sleep(DURATION_SECONDS)
        snapshot = run(["nft", "-a", "list", "table", "inet", TABLE]).stdout
        counters = re.findall(r"\bcounter packets (\d+)\s+bytes", snapshot)
        if len(counters) != 1:
            raise RuntimeError("Cannot verify exact test rule counter")
        print("de_nfq210_peer_bypass_rule_packets=" + counters[0], flush=True)
    finally:
        if nft_has_table():
            run(["nft", "delete", "table", "inet", TABLE], check=False)
        print("de_nfq210_peer_bypass_removed=" + str(not nft_has_table()).lower(),
              flush=True)
    if nft_has_table():
        raise RuntimeError("Timed NFQUEUE bypass was not removed")
    # Original NFQUEUE210 and production services must remain intact.
    audit_rule()
    for svc in ("nginx.service", "mnebydns-dot.service"):
        if run(["systemctl", "is-active", "--quiet", svc],
               check=False).returncode:
            raise RuntimeError("Service unhealthy after controlled test")
    print("de_nfq210_original_rule_preserved=true", flush=True)
    print("de_nfq210_services_unchanged=true", flush=True)
    print("de_nfq210_android_isp=NOT_TESTED", flush=True)


if __name__ == "__main__":
    main()
