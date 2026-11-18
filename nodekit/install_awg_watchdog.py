#!/usr/bin/env python3
"""Install the persistent, fail-closed AmneziaWG peer expiry watchdog.

No service enable/start occurs here. Enrollment with controller public key and
external E2E are separate controlled operations.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from awg_lifecycle import validate as validate_awg, APP
from install_components import node_ready, safe_dir

ROOT = Path("/var/lib/mnebyvpn-nodekit")
UNIT = Path("/etc/systemd/system/mnebyvpn-nodekit-awg-watchdog@.service")


class WatchdogInstallError(ValueError):
    pass


def unit() -> str:
    return """[Unit]
Description=MNEBYVPN AWG 3.1 Ed25519 entitlement and expiry watchdog on %i
Requires=mnebyvpn-nodekit-awg@%i.service
BindsTo=mnebyvpn-nodekit-awg@%i.service
After=mnebyvpn-nodekit-awg@%i.service

[Service]
Type=simple
TimeoutStartSec=30
TimeoutStopSec=20
Environment=PATH=/opt/mnebyvpn-amneziawg:/usr/sbin:/usr/bin:/sbin:/bin
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=/opt/mnebyvpn-amneziawg/amneziawg-go
ExecStartPre=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_peer_grants.py --node-id %i --mode controller-check
ExecStart=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_peer_grants.py --node-id %i --mode watchdog
ExecStopPost=-/opt/mnebyvpn-amneziawg/awg-quick down /var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf
Restart=no
KillMode=control-group
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectHome=true
ProtectSystem=full
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def checked_install(destination: Path, payload: bytes, mode: int) -> None:
    if destination.is_symlink():
        raise WatchdogInstallError("Unexpected installed code symlink")
    if destination.exists():
        st = destination.stat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o022 or destination.read_bytes() != payload):
            raise WatchdogInstallError("Existing code differs; manual migration required")
        return
    fd, staging = tempfile.mkstemp(prefix=".awg-watchdog-", dir=destination.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staging, destination, follow_symlinks=False)
    finally:
        Path(staging).unlink(missing_ok=True)


def install(node: Path, source: Path, *, runner=subprocess.run) -> dict:
    validate_awg(node)
    if source.is_symlink() or not source.is_file() or source.stat().st_uid != 0:
        raise WatchdogInstallError("Untrusted source directory")
    if APP.is_symlink():
        raise WatchdogInstallError("App directory is a symlink")
    safe_dir(APP, private=False)
    worker = "mnebyvpn-nodekit-awg-watchdog@" + node.name + ".service"
    for state in ("is-active", "is-enabled"):
        check = runner(["systemctl", state, "--quiet", worker],
                       timeout=10, capture_output=True, check=False)
        if check.returncode == 0:
            raise WatchdogInstallError("Cannot modify active watchdog")
    checked_install(APP / "awg_peer_grants.py", source.read_bytes(), 0o600)
    checked_install(UNIT, unit().encode(), 0o644)
    runner(["systemctl", "daemon-reload"], capture_output=True,
           check=True, timeout=12)
    return {"node_id": node.name, "installed": True, "watchdog_enabled": False,
            "watchdog_started": False, "subscriber_keys_issued": False,
            "published": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id", required=True)
    p.add_argument("--stage-root", type=Path, default=ROOT)
    args = p.parse_args()
    try:
        if os.geteuid() != 0:
            raise WatchdogInstallError("Root required")
        node = node_ready(args.stage_root, args.node_id)
        print(json.dumps(install(node, Path(__file__).with_name("awg_peer_grants.py")),
                         sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("nodekit_awg_watchdog_install_error=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
