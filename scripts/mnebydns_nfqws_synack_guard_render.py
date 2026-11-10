#!/usr/bin/env python3
"""Fail-closed render-only patch for RU telegram-nfqws-rules.

No SSH, no config writes, and no live firewall changes. Generates an optional
single-peer SYN-ACK exemption before the existing NFQUEUE 210 rule.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

TAG="MNEBYDNS_SYNACK_CANARY_PEER_V1"
QUEUE_LINE='        nft add rule inet telegram_nfqws post oifname "$WAN_IF" tcp sport 443 ct reply packets 1-20 meta mark and 0x40000000 == 0 counter queue num "$QUEUE" bypass comment telegram-nfqws'
CASE_LINE='    apply:\n        remove_all\n'
CONFIG_LINE='SYNACK_FILE="@{MNEBYDNS_SYNACK_CANARY_FILE:-/etc/mnebydns/telegram-synack-canary-ipv4}"'.replace('@{',chr(36)+'{')

BEFORE_REMOVE="""    apply:
        # Validate the opt-in peer before touching the current nft ruleset.
        SYNACK_CLIENT=
        if [ -e "$SYNACK_FILE" ]; then
            [ -f "$SYNACK_FILE" ] && [ -r "$SYNACK_FILE" ] || {
                echo "Invalid SYN-ACK peer configuration" >&2; exit 2;
            }
            [ "$(stat -c %u "$SYNACK_FILE")" = 0 ] || {
                echo "SYN-ACK canary peer file must be root owned" >&2; exit 2;
            }
            SYNACK_CLIENT="$(cat "$SYNACK_FILE")"
            SYNACK_CLIENT="$(python3 - "$SYNACK_CLIENT" <<'PY'
import ipaddress,sys
try:
    ip=ipaddress.IPv4Address(sys.argv[1])
    if not ip.is_global or str(ip)=="188.120.254.223":
        raise ValueError("not an allowed public peer")
    print(ip)
except (ValueError,IndexError) as exc:
    raise SystemExit("Invalid SYN-ACK canary peer: "+str(exc))
PY
)" || exit 2
        fi
        remove_all
"""
GUARD_LINE="""        if [ -n "$SYNACK_CLIENT" ]; then
            nft "add rule inet telegram_nfqws post oifname $WAN_IF ip saddr 188.120.254.223 ip daddr $SYNACK_CLIENT tcp sport 443 tcp flags & (syn | ack) == (syn | ack) ct reply packets 1-20 meta mark and 0x40000000 == 0 counter return comment \\"MNEBYDNS_SYNACK_CANARY_PEER_V1\\""
        fi
"""

def render(original: str) -> str:
    if TAG in original:
        if original.count(TAG)==1 and original.count(QUEUE_LINE)==1:
            return original
        raise ValueError("Unexpected existing canary guard")
    if original.count(QUEUE_LINE)!=1 or original.count(CASE_LINE)!=1:
        raise ValueError("Unrecognized nfqws generator; abort")
    if "nft add table inet telegram_nfqws" not in original or "nft delete table inet telegram_nfqws" not in original:
        raise ValueError("Generator table lifecycle mismatch")
    if "WAN_IF=ens3" not in original or "QUEUE=210" not in original:
        raise ValueError("Unexpected WAN or queue number")
    if "SYNACK_FILE=" in original:
        raise ValueError("Existing SYNACK_FILE assignment")
    result=original.replace("QUEUE=210\n","QUEUE=210\n"+CONFIG_LINE+"\n",1)
    result=result.replace(CASE_LINE,BEFORE_REMOVE,1)
    result=result.replace(QUEUE_LINE,GUARD_LINE+QUEUE_LINE,1)
    return result

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path)
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    modified=render(args.source.read_text())
    if args.check:
        print("nfqws_synack_patch=VALIDATED_ONLY")
    else:
        sys.stdout.write(modified)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
