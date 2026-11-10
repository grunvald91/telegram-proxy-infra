#!/usr/bin/env python3
"""Owner-operated 60s RU SYN-ACK queue-210 bypass A/B experiment.

One explicitly allowed public IPv4, TCP SYN-ACK from RU :443 ONLY.
This must NEVER be run from GitHub Actions or deployed automatically.
Runs from an already authenticated SSH session, with an independent systemd
rollback timer armed BEFORE inserting the temporary nft rule.
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

SERVER = "188.120.254.223"
TABLE = ("inet", "telegram_nfqws", "post")
TAG_PREFIX = "MNEBY_IG_SYNACK_AB_"
ROLLBACK_AFTER = 95
ACTIVE_SECONDS = 55
LOCK = "/run/lock/mnebydns-ig-synack-ab.lock"
ROLLBACK_DIR = Path("/run/mnebydns-ig-ab")


def shell(args, *, input=None, check=True, timeout=12):
    return subprocess.run(
        args, input=input, text=True, capture_output=True,
        check=check, timeout=timeout,
    )


def chain():
    return shell(["nft", "-a", "list", "chain", *TABLE]).stdout


def tagged_handles(text, tag):
    matches = []
    for line in text.splitlines():
        if f'comment "{tag}"' not in line:
            continue
        match = re.search(r"# handle (\d+)\s*$", line)
        if match:
            matches.append(int(match.group(1)))
    return matches


def counts(text, tag):
    for line in text.splitlines():
        if f'comment "{tag}"' in line:
            match = re.search(r"\bcounter packets (\d+) bytes (\d+)", line)
            if match:
                return tuple(int(x) for x in match.groups())
    return None


def ensure_preflight(current):
    # Abort instead of editing a changed or unfamiliar chain.
    expected = re.search(
        r"chain post\s*\{\s*type filter hook postrouting\b[^;]*;\s*policy accept;",
        current,
    )
    if not expected:
        raise RuntimeError("Expected postrouting filter base chain with ACCEPT policy not found")
    queued = [x for x in current.splitlines()
              if "tcp sport 443" in x and
              re.search(r"\bqueue\b.*\bto\s+210\b", x) and
              "bypass" in x]
    if len(queued) != 1:
        raise RuntimeError("Expected exactly one marked NFQUEUE 210 sport 443 rule")
    if "mark" not in queued[0]:
        raise RuntimeError("Queue 210 rule has unexpected missing mark predicate")
    if TAG_PREFIX in current:
        raise RuntimeError("Another Instagram test bypass rule is present")


def write_watchdog(path: Path, tag: str):
    # Baked-in exact tag; watchdog needs neither the parent session nor repo.
    script = f'''#!/usr/bin/env python3
import os, re, subprocess
tag={tag!r}
table=["inet","telegram_nfqws","post"]
try:
    r=subprocess.run(["nft","-a","list","chain",*table],capture_output=True,text=True,timeout=10)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if f'comment "{{tag}}"' not in line: continue
            m=re.search(r"# handle (\\d+)\\s*$",line)
            if m:
                subprocess.run(["nft","delete","rule",*table,"handle",m.group(1)],timeout=10,check=True)
                print("synack_ab_watchdog=RULE_DELETED",flush=True)
finally:
    try: os.unlink({str(path)!r})
    except FileNotFoundError: pass
'''
    with path.open("x") as file:
        file.write(script)
    path.chmod(0o700)


def remove_own(tag: str):
    current = chain()
    handles = tagged_handles(current, tag)
    if len(handles) > 1:
        raise RuntimeError("Found multiple tagged bypass rules; refusing ambiguous cleanup")
    for handle in handles:
        shell(["nft", "delete", "rule", *TABLE, "handle", str(handle)])
    return len(handles)


def make_rule(peer: str, tag: str) -> str:
    return (
        f'insert rule inet telegram_nfqws post '
        f'ip saddr {SERVER} ip daddr {peer} '
        'tcp sport 443 tcp flags & (syn | ack) == (syn | ack) '
        f'counter return comment "{tag}"\\n'
    )


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root from authorized SSH")
    if len(sys.argv) == 2 and sys.argv[1] == "--validate-only":
        ensure_preflight(chain())
        test_rule = make_rule("192.0.2.45", "MNEBY_IG_SYNACK_AB_DRY_RUN_ONLY")
        shell(["nft", "--check", "-f", "-"], input=test_rule)
        print("queue210_live_chain_preflight=PASS", flush=True)
        print("queue210_live_rule_check_only=PASS_NO_CHANGES", flush=True)
        return
    if len(sys.argv) != 3:
        raise SystemExit("Usage: root python3 - TEST_PEER_PUBLIC_IPV4 UNIQUE_NUMERIC_RUN_ID")
    if not all(shutil.which(x) for x in ("nft", "systemd-run", "systemctl", "python3")):
        raise RuntimeError("Missing required system tools")
    peer = str(ipaddress.IPv4Address(sys.argv[1]))
    if not ipaddress.IPv4Address(peer).is_global or peer == SERVER:
        raise RuntimeError("Only distinct public IPv4 peer is supported")
    runid = sys.argv[2]
    if not re.fullmatch(r"\d{8,16}", runid):
        raise RuntimeError("Run ID must be 8-16 digits")
    tag = TAG_PREFIX + runid
    unit = "mneby-ig-ab-" + runid
    LOCKDIR = Path(LOCK).parent
    LOCKDIR.mkdir(parents=True, exist_ok=True)
    with open(LOCK, "a") as locked:
        try:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("A queue-210 experiment is already active")

        ensure_preflight(chain())
        status = shell(["systemctl", "is-active", unit + ".timer"], check=False)
        if status.returncode == 0:
            raise RuntimeError("Existing systemd rollback timer for this run ID")

        ROLLBACK_DIR.mkdir(mode=0o700, exist_ok=True)
        if ROLLBACK_DIR.is_symlink():
            raise RuntimeError("Invalid rollback directory")
        ROLLBACK_DIR.chmod(0o700)
        rollback = ROLLBACK_DIR / ("rollback-" + runid + ".py")
        write_watchdog(rollback, tag)

        rule = make_rule(peer, tag)
        # -c validates grammar and existing chain but makes no rule changes.
        shell(["nft", "--check", "-f", "-"], input=rule)
        try:
            # Schedule durable cleanup first, then modify exactly one nft rule.
            shell([
                "systemd-run", "--quiet", "--collect", "--unit", unit,
                f"--on-active={ROLLBACK_AFTER}s",
                "/usr/bin/python3", str(rollback),
            ])
            active = shell(["systemctl", "is-active", unit + ".timer"], check=False)
            if active.returncode != 0:
                raise RuntimeError("Independent rollback timer did not become active")
            shell(["nft", "-f", "-"], input=rule)
            handles = tagged_handles(chain(), tag)
            if len(handles) != 1:
                raise RuntimeError("Temporary exact-match rule not uniquely installed")
            print("synack_ab_test=READY", flush=True)
            print("synack_ab_scope=single_peer_ipv4_synack_443_only", flush=True)
            print("synack_ab_independent_rollback=ARMED", flush=True)
            print(f"synack_ab_duration_seconds={ACTIVE_SECONDS}", flush=True)
            time.sleep(ACTIVE_SECONDS)
            print("synack_ab_rule_counter=" + str(counts(chain(), tag)), flush=True)
        finally:
            try:
                number = remove_own(tag)
                print("synack_ab_immediate_cleanup=" + ("DONE" if number else "ALREADY_REMOVED"), flush=True)
            except Exception as exc:
                print("synack_ab_immediate_cleanup=FAILED_TIMER_STILL_ARMED", flush=True)
                print("cleanup_exception_type=" + type(exc).__name__, flush=True)
                raise


if __name__ == "__main__":
    main()
