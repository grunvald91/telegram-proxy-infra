#!/usr/bin/env python3
"""Parse optional independently supplied SSH known_hosts for a fixed fleet IPv4.

Outputs ONLY the Ed25519 public key's base64 (never credentials). Empty input
means the controller's first-contact TOFU policy is used. Any nonempty
malformed/mismatched preapproval aborts BEFORE the controller writes a pin.
"""
from __future__ import annotations

import argparse
import os
import sys
from fleet_host_trust import canonical_key, public_ipv4, TrustError


def expected_key_from_known_hosts(known: str, ip: str) -> str | None:
    public_ipv4(ip)
    if not known:
        return None
    records = [line.split() for line in known.splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    if len(records) != 1 or len(records[0]) not in (3, 4):
        raise TrustError("Expected exactly one approved SSH host key record")
    entry = records[0]
    if ip not in entry[0].split(","):
        raise TrustError("Approved host key is for another VPS")
    return canonical_key(f"{ip} {entry[1]} {entry[2]}", ip).split()[2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True)
    args = parser.parse_args()
    try:
        key = expected_key_from_known_hosts(os.environ.get("PREAPPROVED_SSH_KNOWN_HOSTS", ""),
                                             args.ip)
        print(key or "")
        return 0
    except (ValueError, TypeError) as exc:
        print("APPROVED_SSH_HOST_PIN_REJECTED=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
