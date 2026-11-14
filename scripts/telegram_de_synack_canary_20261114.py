#!/usr/bin/env python3
"""Temporary runner-address-only foreign TCP443 SYNACK proof (no persistent config).
Requires root. Install independently timed rollback before inserting a live nft rule.
Never prints caller addresses, key material, live firewall rules, or proxy secrets.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BASE = Path("/root/proxy-backups")
SOURCE = Path("/usr/local/sbin/telegram-foreign-nfqws-rules")
CONF = Path("/etc/zapret2/telegram-nfqws.conf")

def exec_checked(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and p.returncode:
        raise RuntimeError("command_failed:" + args[0])
    return p

def state(runid):
    if not re.fullmatch(r"[0-9]{8,20}", runid):
        raise ValueError("invalid_run_id")
    return BASE / ("telegram-de-synack-canary-" + runid)

def marker(runid):
    return "telegram_de_synack_canary_" + runid[-10:]

def get_rules():
    p = exec_checked("nft", "-j", "-a", "list", "chain", "inet", "telegram_nfqws", "post")
    return [item["rule"] for item in json.loads(p.stdout).get("nftables", []) if "rule" in item]

def find_marker(runid):
    return [row for row in get_rules() if row.get("comment") == marker(runid)]

def remove(runid):
    for row in find_marker(runid):
        exec_checked("nft", "delete", "rule", "inet", "telegram_nfqws", "post", "handle", str(row["handle"]))
    if find_marker(runid):
        raise RuntimeError("canary_not_removed")
    print("CANARY_RULE_REMOVED=true", flush=True)

def install(runid, ip):
    if os.geteuid():
        raise RuntimeError("root_required")
    caller = ipaddress.ip_address(ip)
    if caller.version != 4 or not caller.is_global:
        raise ValueError("caller_not_public_ipv4")
    if not SOURCE.is_file() or not CONF.is_file():
        raise RuntimeError("expected_foreign_config_missing")
    if "synack_split" not in CONF.read_text(errors="replace"):
        raise RuntimeError("foreign_synack_split_not_enabled")
    if exec_checked("systemctl", "is-active", "--quiet", "telegram-foreign-nfqws.service", check=False).returncode:
        raise RuntimeError("foreign_nfqws_inactive")
    rules = get_rules()
    queues = [r for r in rules if any("queue" in x for x in r.get("expr", []))]
    if len(queues) != 1 or find_marker(runid):
        raise RuntimeError("unexpected_nft_baseline")
    folder = state(runid)
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        local = folder / "rollback.py"
        shutil.copyfile(__file__, local)
        local.chmod(0o700)
        unit = "telegram-de-synack-" + runid
        # Timer creation precedes any networking mutation.
        exec_checked("systemd-run", "--quiet", "--unit=" + unit, "--on-active=120s",
                     "/usr/bin/python3", str(local), "rollback", runid)
        if exec_checked("systemctl", "is-active", "--quiet", unit + ".timer", check=False).returncode:
            raise RuntimeError("timer_not_armed")
        args = ["insert", "rule", "inet", "telegram_nfqws", "post", "oifname", "eth0",
                "ip", "daddr", str(caller), "tcp", "sport", "443",
                "tcp", "flags", "&", "(", "syn", "|", "ack", ")", "==",
                "(", "syn", "|", "ack", ")", "counter", "accept", "comment", marker(runid)]
        exec_checked("nft", "-c", *args)
        exec_checked("nft", *args)
        actual = get_rules()
        mine = [i for i, r in enumerate(actual) if r.get("comment") == marker(runid)]
        queue_indices = [i for i, r in enumerate(actual) if any("queue" in e for e in r.get("expr", []))]
        if len(mine) != 1 or not queue_indices or mine[0] >= min(queue_indices):
            raise RuntimeError("canary_not_before_nfqueue")
        print("CANARY_INSTALLED=true", flush=True)
        print("CANARY_AUTOROLLBACK_ARMED=true", flush=True)
    except BaseException:
        try:
            remove(runid)
        finally:
            raise

def rollback(runid):
    if os.geteuid():
        raise RuntimeError("root_required")
    remove(runid)
    unit = "telegram-de-synack-" + runid
    exec_checked("systemctl", "stop", unit + ".timer", check=False)
    print("CANARY_CLEANUP_DONE=true", flush=True)

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "install":
        install(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "rollback":
        rollback(sys.argv[2])
    else:
        raise SystemExit("usage: install RUNID IP | rollback RUNID")
