#!/usr/bin/env python3
"""Resolve an approved NEW VPS exactly once for pinned SSH transport.

GitHub Actions must never re-resolve an operator-supplied alias between the
production-IP safety check and SSH/SCP. SSH still validates the manually
pinned HostKeyAlias from the configured known_hosts secret.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sys
from typing import Callable

# Production ingress and foreign egress nodes are not installation targets.
PROTECTED_IPS = frozenset({"89.125.90.101", "188.120.254.223"})
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]")


class TargetError(ValueError):
    pass


def safe_target_ip(
    host: str,
    resolver: Callable[..., list] = socket.getaddrinfo,
) -> str:
    if not isinstance(host, str) or len(host) > 253 or not HOST.fullmatch(host):
        raise TargetError("Invalid new-VPS SSH host")
    if ".." in host or host.endswith(".") or (
        "." in host and any(label.startswith("-") or label.endswith("-")
                            for label in host.split("."))):
        raise TargetError("Invalid DNS host labels")
    try:
        entries = resolver(host, None, type=socket.SOCK_STREAM)
        addresses = {ipaddress.ip_address(item[4][0]) for item in entries}
    except (OSError, ValueError, IndexError, KeyError) as exc:
        raise TargetError("New VPS hostname could not be resolved") from exc
    if not addresses or any(
        str(address) in PROTECTED_IPS or not address.is_global
        for address in addresses
    ):
        raise TargetError("Target contains a protected or non-public server IP")
    # An SSH command can now be pinned to exactly this resolved IP.
    v4 = sorted((addr for addr in addresses if addr.version == 4),
                key=lambda addr: int(addr))
    v6 = sorted((addr for addr in addresses if addr.version == 6),
                key=lambda addr: int(addr))
    return str((v4 or v6)[0])


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        print(safe_target_ip(sys.argv[1]))
        return 0
    except TargetError:
        # Never print target credentials or secrets into workflow logs.
        print("new_vps_target_validation_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
