#!/usr/bin/env python3
"""RU read-only audit of the exact creator of nft queue210.

Outputs only structural booleans and SHA256 (never full script content,
application configuration or credentials). This script NEVER changes files.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import subprocess
import sys

RULES=Path("/usr/local/sbin/telegram-nfqws-rules")
UNIT=Path("/etc/systemd/system/telegram-nfqws.service")
MARK="MNEBY_IG_SYNACK"
def report(k, value):
    print(f"{k}={value}",flush=True)

def main():
    if not RULES.is_file() or not UNIT.is_file():
        report("nfqws_generator_exists", RULES.is_file())
        report("nfqws_unit_exists", UNIT.is_file())
        return 2
    raw=RULES.read_bytes()
    unit=UNIT.read_text(errors="replace")
    s=raw.decode("utf-8",errors="replace")
    report("nfqws_generator_sha256",hashlib.sha256(raw).hexdigest())
    report("nfqws_generator_executable",bool(RULES.stat().st_mode & 0o111))
    report("nfqws_generator_nft_family", "inet:telegram_nfqws" if "inet telegram_nfqws" in s else "OTHER")
    report("nfqws_generator_recreates_table",bool(re.search(r"nft\s+delete\s+table\s+inet\s+telegram_nfqws",s)))
    report("nfqws_generator_creates_base_chain",bool(re.search(r"add chain inet telegram_nfqws post",s)))
    queue_lines=[line.strip() for line in s.splitlines() if "queue" in line and ("$QUEUE" in line or "210" in line)]
    report("nfqws_generator_queue_rule_count",len(queue_lines))
    for line in queue_lines[:5]:
        report("nfqws_generator_queue_rule_has_sport443",bool(re.search(r"tcp\s+sport\s+443",line)))
        report("nfqws_generator_queue_rule_has_oifname", "oifname" in line)
        report("nfqws_generator_queue_rule_has_reply_packets", "ct reply packets" in line)
        report("nfqws_generator_queue_rule_has_bypass", "bypass" in line)
        report("nfqws_generator_queue_rule_has_meta_mark", "meta mark" in line)
    report("nfqws_generator_existing_synack_guard",MARK in s)
    report("nfqws_unit_sha256",hashlib.sha256(unit.encode()).hexdigest())
    report("nfqws_unit_has_generator_apply",bool(re.search(r"ExecStartPost=.*telegram-nfqws-rules apply",unit)))
    report("nfqws_unit_has_generator_remove",bool(re.search(r"ExecStopPost=.*telegram-nfqws-rules remove",unit)))
    report("nfqws_unit_restart_auto",bool(re.search(r"Restart=always",unit)))
    p=subprocess.run(["nft","-a","list","chain","inet","telegram_nfqws","post"],
                     capture_output=True,text=True,timeout=10)
    if p.returncode:
        report("nfqws_live_post_chain","UNAVAILABLE")
        return 3
    lines=p.stdout.splitlines()
    live_queue=[x for x in lines if "tcp sport 443" in x and "to 210" in x]
    report("nfqws_live_queue_rule_count",len(live_queue))
    report("nfqws_live_queue_has_synack_guard",MARK in p.stdout)
    report("nfqws_live_queue_has_reply_packets",all("ct reply packets" in x for x in live_queue))
    report("nfqws_generator_audit","READ_ONLY_COMPLETE")
    return 0

if __name__=="__main__":
    sys.exit(main())
