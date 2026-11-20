#!/usr/bin/env python3
"""Only FI217: prepare and tear down one synthetic AWG test via forced SSH.

Controller-signed synthetic grant/revoke is NEVER issued to a real device.
The existing 95s systemd hard-stop timer is armed BEFORE AWG starts.
No production entitlements or subscribers are touched. Emergency cleanup
attempts to apply the pre-signed revoke when PostgreSQL or CI fails.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
import tempfile

import fi_awg_applied_disposable_canary as live
import fi_awg_signed_canary as signed


def prepare(bundle:Path) -> None:
    live.preflight(bundle)
    live.phase("DB_E2E_WATCHDOG_INSTALL_BEGIN")
    live.install_watchdog()
    live.call_or_block([
        "/usr/bin/systemd-run","--quiet","--collect",
        "--unit="+live.TIMER,"--on-active=95s",
        "/usr/bin/systemctl","stop",live.WATCHDOG,live.UNIT,
    ],"disposable_timeout_not_armed",12)
    live.phase("DB_E2E_INDEPENDENT_KILL_TIMER_ARMED")
    try:
        live.call_or_block(["/usr/bin/systemctl","start",live.UNIT],
                           "db_e2e_awg_start_failed",48)
        live.call_or_block(["/usr/bin/systemctl","start",live.WATCHDOG],
                           "db_e2e_watchdog_start_failed",22)
        if (live.systemd_active_state(live.UNIT)!="active" or
                live.systemd_active_state(live.WATCHDOG)!="active"):
            live.block("db_e2e_live_awg_or_watchdog_missing")
    except BaseException:
        # On a partial startup leave the independent kill timer armed.
        raise
    print("FI_AWG_E2E_FI=PREPARED;KILL_TIMER_SECONDS=95;"
          "LIVE_PEERS=0;CUSTOMER_RELEASE=false")


def cleanup(bundle:Path) -> None:
    if not signed.is_host(signed.FI_IP):
        live.block("db_e2e_cleanup_wrong_node")
    data=json.loads(signed.protected(bundle,6000))
    grant=data["grant"]
    revoke=data["revoke"]
    status=live.residual_ledger_status()
    if status=="UNVERIFIED":
        live.block("db_e2e_cleanup_untrusted_ledger")
    if status=="OTHER_ENTITLEMENTS_PRESENT":
        # Recognize ONLY our exact signed grant, not another entitlement.
        from awg_peer_grants import validate_state
        state=validate_state(json.loads(signed.protected(live.LEDGER,50000)),live.NODE)
        rows=state["grants"]
        if (set(rows)!={grant["entitlementId"]} or
                rows[grant["entitlementId"]]["peerPublicKey"]!=grant["peerPublicKey"] or
                rows[grant["entitlementId"]]["clientIpv4"]!=grant["clientIpv4"] or
                rows[grant["entitlementId"]]["revision"]!=1 or
                rows[grant["entitlementId"]]["enabled"] is not True):
            live.block("db_e2e_cleanup_non_synthetic_ledger")
    if status not in ("ONLY_REVOKED_DISPOSABLE","ABSENT"):
        if (live.systemd_active_state(live.UNIT)!="active" or
                live.systemd_active_state(live.WATCHDOG)!="active"):
            live.block("db_e2e_emergency_revoke_requires_live_watchdog")
        # A previous or interrupted database step might have applied grant
        # but not revoke. Apply ONLY the exact pre-signed synthetic revoke.
        with tempfile.TemporaryDirectory(prefix="fi-awg-e2e-revoke-",dir="/run") as tmp:
            live.run_apply(revoke,Path(tmp))
        live.phase("DB_E2E_EMERGENCY_REVOKE_APPLIED")
    if live.live_peers() if live.systemd_active_state(live.UNIT)=="active" else False:
        live.block("db_e2e_cleanup_live_peer_still_present")
    if not live.safe_cleanup(grant):
        live.block("db_e2e_cleanup_failed_kill_timer_remains_armed")
    print("FI_AWG_E2E_FI=CLEANED;LIVE_PEERS=0;AWG_ACTIVE=false;"
          "WATCHDOG_ACTIVE=false;KILL_TIMER_ACTIVE=false;CUSTOMER_RELEASE=false")


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("prepare","cleanup"),required=True)
    parser.add_argument("--signed",type=Path,required=True)
    args=parser.parse_args()
    if args.mode=="prepare":
        prepare(args.signed)
    else:
        cleanup(args.signed)


if __name__=="__main__":
    try:
        main()
    except (live.CanaryBlocked,signed.CanaryError,OSError,ValueError,
            TypeError,UnicodeError,KeyError):
        raise SystemExit(2)
