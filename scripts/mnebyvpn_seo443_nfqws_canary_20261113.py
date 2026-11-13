#!/usr/bin/env python3
"""Short source-only NFQUEUE canary on RU ingress; independent rollback."""
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
import time

if len(sys.argv) != 3:
    raise SystemExit("Usage: script.py <runner_ipv4> <run_id>")
client = str(ipaddress.IPv4Address(sys.argv[1]))
run_id = sys.argv[2]
if not re.fullmatch(r"[0-9]{8,20}", run_id):
    raise SystemExit("Bad run id")
marker = "seo443_canary_" + run_id
unit = "mnebyvpn-seo443-" + run_id
rollback_file = pathlib.Path("/run/" + unit + "-rollback.py")


def execute(*args, strict=True, timeout=12):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if strict and p.returncode:
        raise RuntimeError("Command failed: " + args[0])
    return p


def chain():
    out = execute("nft", "-j", "-a", "list", "chain",
                  "inet", "telegram_nfqws", "post")
    return [item["rule"] for item in json.loads(out.stdout)["nftables"]
            if "rule" in item]


def matching():
    return [item for item in chain() if item.get("comment") == marker]


def assert_safe_environment():
    for service in ("telegram-nfqws.service", "nginx.service"):
        assert execute("systemctl", "is-active", "--quiet", service,
                       strict=False).returncode == 0, service
    conf = pathlib.Path("/etc/zapret2/telegram-nfqws.conf").read_text()
    assert "synack_split" in conf and "--qnum=210" in conf
    queue = []
    for rule in chain():
        expr = rule.get("expr", [])
        if any("queue" in e and e["queue"].get("num") == 210
               for e in expr):
            queue.append(json.dumps(expr))
    assert len(queue) == 1, "Expected one existing queue rule"
    assert '"ens3"' in queue[0] and '"sport"' in queue[0]
    assert '"right": 443' in queue[0]
    assert not matching(), "Canary already active"


# The watchdog script checks a unique marker before removing a rule,
# so it cannot remove a different or later rule if handles are reused.
ROLLBACK_CODE = """
import json, pathlib, subprocess, sys
marker = sys.argv[1]
p = subprocess.run(["nft", "-j", "-a", "list", "chain",
                    "inet", "telegram_nfqws", "post"],
                   capture_output=True, text=True)
if p.returncode == 0:
    for item in json.loads(p.stdout).get("nftables", []):
        rule = item.get("rule", {})
        if rule.get("comment") == marker:
            subprocess.run(["nft", "delete", "rule", "inet",
                            "telegram_nfqws", "post", "handle",
                            str(rule["handle"])], check=True)
pathlib.Path(__file__).unlink(missing_ok=True)
"""

assert_safe_environment()
rollback_file.write_text(ROLLBACK_CODE)
rollback_file.chmod(0o700)
armed = False
try:
    # Arm watchdog BEFORE inserting the exception. It survives SSH loss.
    execute("systemd-run", "--quiet", "--unit=" + unit,
            "--on-active=70s", "/usr/bin/python3",
            str(rollback_file), marker)
    armed = True
    assert execute("systemctl", "is-active", "--quiet",
                   unit + ".timer", strict=False).returncode == 0
    # Single source and TCP sport 443, existing chain only.
    execute("nft", "insert", "rule", "inet", "telegram_nfqws", "post",
            "ip", "daddr", client, "tcp", "sport", "443", "counter",
            "accept", "comment", marker)
    assert len(matching()) == 1, "Canary rule not verifiable"
    print("CANARY_SCOPED_ACCEPT_ACTIVE=true", flush=True)
    print("CANARY_WATCHDOG_ARMED=true", flush=True)
    time.sleep(30)
finally:
    # Immediate best-effort cleanup. Leave watchdog armed if it fails.
    result = execute("/usr/bin/python3", str(rollback_file), marker,
                     strict=False) if rollback_file.exists() else None
    rule_present = bool(matching())
    if not rule_present:
        if armed:
            execute("systemctl", "stop", unit + ".timer", strict=False)
        rollback_file.unlink(missing_ok=True)
        print("CANARY_REMOVED_VERIFIED=true", flush=True)
    else:
        print("CANARY_ROLLBACK_PENDING_WATCHDOG=true", flush=True)
        raise RuntimeError("Source-only rule cleanup unverified")
