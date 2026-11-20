#!/usr/bin/env python3
"""FI217 reserved temporary E2E slot inventory. Strictly read-only; no PII."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

NODE = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
IP = "10.73.91.253"
class Blocked(ValueError):
    pass

def examine() -> tuple[str, str]:
    sys.path.insert(0, "/opt/mnebyvpn-nodekit")
    from awg_peer_grants import protected_file, validate_state
    import fi_awg_signed_canary as canary
    if os.geteuid() != 0 or not canary.is_host(canary.FI_IP):
        raise Blocked("unexpected host")
    file = NODE / "amneziawg/peer-grants.json"
    if file.exists() or file.is_symlink():
        data=validate_state(json.loads(protected_file(file)), NODE.name)
        rows=[item for item in data["grants"].values() if item["clientIpv4"] == IP]
        if len(rows)>1: raise Blocked("reserved address reused")
        state=("ABSENT" if not rows else
               "REVOKED" if rows[0]["enabled"] is False and
                            rows[0]["expiresAt"] is None else "ACTIVE")
    else:
        state="ABSENT"
    result=subprocess.run(
        ["/opt/mnebyvpn-amneziawg/awg", "show", "awg0", "allowed-ips"],
        capture_output=True,text=True,timeout=8,check=True)
    if len(result.stdout)>100000:raise Blocked("unknown allowed ip output")
    bound=sum(1 for line in result.stdout.splitlines()
              if line.split()[-1:]==[IP+"/32"])
    if bound not in (0,1):raise Blocked("multiple live reserved peers")
    return state, "YES" if bound else "NO"

def main()->int:
    try:
        state,live=examine()
        print("FI_AWG_HEALTH_SLOT_LEDGER="+state)
        print("FI_AWG_HEALTH_SLOT_ACTIVE="+live)
        return 0
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
        print("FI_AWG_HEALTH_SLOT=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
