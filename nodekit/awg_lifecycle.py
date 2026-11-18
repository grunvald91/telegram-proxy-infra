#!/usr/bin/env python3
"""Install and smoke-test the REAL AmneziaWG 3.1 server on a new VPS.

Install is non-activating. Canary briefly starts the peerless AmneziaWG
userspace interface under systemd, validates it and always stops it.
Never changes host firewall, forwarding, NAT, existing subscribers or routes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from install_components import safe_dir, safe_manifest, node_ready, digest

STAGE = Path("/var/lib/mnebyvpn-nodekit")
APP = Path("/opt/mnebyvpn-nodekit")
AWG_BIN = Path("/opt/mnebyvpn-amneziawg")
UNIT_PATH = Path("/etc/systemd/system/mnebyvpn-nodekit-awg@.service")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
INTERFACE = "awg0"
PORT = 51821


class AwgLifecycleError(ValueError):
    pass


def unit_source() -> str:
    # Deliberately no ExecStartPost firewall mutations, iptables, NAT or
    # client assignments. The AmneziaWG userspace fallback is explicitly set.
    return """[Unit]
Description=MNEBYVPN Nodekit isolated AmneziaWG 3.1 on %i
Documentation=https://github.com/amnezia-vpn/amneziawg-go
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=40
TimeoutStopSec=25
Environment=PATH=/opt/mnebyvpn-amneziawg:/usr/sbin:/usr/bin:/sbin:/bin
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=/opt/mnebyvpn-amneziawg/amneziawg-go
ExecStartPre=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_lifecycle.py --node-id %i --mode validate
ExecStart=/opt/mnebyvpn-amneziawg/awg-quick up /var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf
ExecStop=/opt/mnebyvpn-amneziawg/awg-quick down /var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf
KillMode=control-group
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def runner(cmd: list[str], *, timeout: int = 25, check: bool = True):
    return subprocess.run(cmd, timeout=timeout, check=check, capture_output=True, text=True)


def checked_file(path: Path, limit: int = 100000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AwgLifecycleError("Missing or symlinked Nodekit file")
    s = path.stat()
    if (s.st_uid != 0 or s.st_mode & 0o077 or not 1 <= s.st_size <= limit):
        raise AwgLifecycleError("Unsafe Nodekit file owner or mode")
    return path.read_bytes()


def validate(node: Path) -> dict:
    manifest = safe_manifest(node / "manifest.json")
    awg = safe_manifest(node / "amneziawg" / "manifest.json")
    conf = checked_file(node / "amneziawg" / "awg0.conf")
    text = conf.decode("ascii")
    hashes = awg.get("source_binary_sha256")
    if (manifest.get("node_id") != node.name or
            manifest.get("state") != "testing" or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False or
            awg.get("node_id") != node.name or
            awg.get("state") != "staged" or
            awg.get("activation_enabled") is not False or
            awg.get("peers_enabled") is not False or
            awg.get("subscribers_enabled") is not False or
            awg.get("protocol") != "AmneziaWG 3.1" or
            awg.get("port") != PORT or
            not isinstance(hashes, dict) or
            set(hashes) != {"awg", "awg-quick", "amneziawg-go"} or
            hashlib.sha256(conf).hexdigest() != awg.get("config_sha256") or
            text.count("[Interface]") != 1 or
            "[Peer]" in text or
            f"ListenPort = {PORT}" not in text or
            "HeaderProtectionKey = " not in text or
            "RandomTrailers = on" not in text or
            "Table = off" not in text or
            "PostUp" in text or "PreUp" in text or
            "PostDown" in text or "PreDown" in text):
        raise AwgLifecycleError("AmneziaWG staged config changed or subscribers exist")
    safe_dir(AWG_BIN, private=False)
    for name, expected in hashes.items():
        p = AWG_BIN / name
        if (not isinstance(expected, str) or
                not re.fullmatch(r"[0-9a-f]{64}", expected) or
                p.is_symlink() or not p.is_file() or
                p.stat().st_uid != 0 or p.stat().st_mode & 0o022 or
                not p.stat().st_mode & stat.S_IXUSR or digest(p) != expected):
            raise AwgLifecycleError("AmneziaWG executable does not match pinned SHA-256")
    return {"node_id": node.name, "backend": "amneziawg-go",
            "port": PORT, "zero_peers": True, "source_verified": True,
            "published": False}


def install(source: Path) -> dict:
    if source.is_symlink() or not source.is_file() or source.stat().st_uid != 0:
        raise AwgLifecycleError("Untrusted installer source")
    if APP.is_symlink():
        raise AwgLifecycleError("Nodekit app path is symlinked")
    APP.mkdir(mode=0o755, parents=True, exist_ok=True)
    safe_dir(APP, private=False)
    target = APP / "awg_lifecycle.py"
    if target.is_symlink():
        raise AwgLifecycleError("Unexpected Nodekit app symlink")
    code = source.read_bytes()
    if target.exists():
        if checked_file(target) != code:
            raise AwgLifecycleError("Installed code drift, refusing overwrite")
    else:
        _install_bytes(target, code, 0o600)
    unit = unit_source().encode()
    if UNIT_PATH.is_symlink():
        raise AwgLifecycleError("Systemd unit symlink forbidden")
    if UNIT_PATH.exists():
        if (UNIT_PATH.stat().st_uid != 0 or
                UNIT_PATH.stat().st_mode & 0o022 or
                UNIT_PATH.read_bytes() != unit):
            raise AwgLifecycleError("Existing systemd unit differs, refusing overwrite")
    else:
        _install_bytes(UNIT_PATH, unit, 0o644)
    runner(["systemctl", "daemon-reload"])
    return {"installed": True, "enabled": False, "started": False,
            "published": False}


def _install_bytes(path: Path, content: bytes, mode: int) -> None:
    fd, temp = tempfile.mkstemp(prefix=".nodekit-install-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, path, follow_symlinks=False)
    finally:
        Path(temp).unlink(missing_ok=True)


def unit_name(node_id: str) -> str:
    if not NAME.fullmatch(node_id) or node_id.endswith("-"):
        raise AwgLifecycleError("Invalid node ID")
    return "mnebyvpn-nodekit-awg@" + node_id + ".service"


def active_unit(unit: str) -> bool:
    return runner(["systemctl", "is-active", "--quiet", unit],
                  check=False).returncode == 0


def enabled_unit(unit: str) -> bool:
    return runner(["systemctl", "is-enabled", "--quiet", unit],
                  check=False).returncode == 0


def inspect(node: Path) -> dict:
    report = validate(node)
    unit = unit_name(node.name)
    return dict(report, systemd_active=active_unit(unit),
                systemd_enabled=enabled_unit(unit))


def canary(node: Path) -> dict:
    report = validate(node)
    unit = unit_name(node.name)
    if (not UNIT_PATH.is_file() or UNIT_PATH.is_symlink() or
            UNIT_PATH.read_text() != unit_source() or
            not (APP / "awg_lifecycle.py").is_file() or
            (APP / "awg_lifecycle.py").read_bytes() != Path(__file__).read_bytes()):
        raise AwgLifecycleError("Cannot start without current installed service")
    if active_unit(unit) or enabled_unit(unit):
        raise AwgLifecycleError("Refusing to reuse enabled or active interface")
    with_path = Path("/sys/class/net") / INTERFACE
    if with_path.exists():
        raise AwgLifecycleError("AWG interface already exists")
    try:
        runner(["systemctl", "start", unit], timeout=65)
        for _ in range(12):
            if active_unit(unit):
                break
            time.sleep(0.25)
        if not active_unit(unit):
            raise AwgLifecycleError("AWG service did not remain active")
        peers = runner([str(AWG_BIN / "awg"), "show", INTERFACE, "peers"]).stdout
        if peers.strip():
            raise AwgLifecycleError("Canary unexpectedly has authorized peers")
        listened = runner([str(AWG_BIN / "awg"), "show", INTERFACE, "listen-port"]).stdout
        if listened.strip() != str(PORT):
            raise AwgLifecycleError("AWG not bound to planned UDP port")
        address = runner(["ip", "-o", "-4", "addr", "show", "dev", INTERFACE]).stdout
        if "10.73.91.1/24" not in address:
            raise AwgLifecycleError("AWG test subnet not configured")
        return dict(report, systemd_started=True, verified_zero_peers=True,
                    expected_udp_port=PORT, transient_only=True,
                    external_client_e2e_verified=False)
    finally:
        runner(["systemctl", "stop", unit], timeout=35, check=False)
        if active_unit(unit):
            raise AwgLifecycleError("AWG canary failed to stop")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--mode", choices=("validate", "install", "canary", "inspect"),
                        required=True)
    parser.add_argument("--stage-root", type=Path, default=STAGE)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise AwgLifecycleError("Root required")
        node = node_ready(args.stage_root, args.node_id)
        safe_dir(node / "amneziawg")
        report = validate(node)
        if args.mode == "install":
            report.update(install(Path(__file__)))
        elif args.mode == "canary":
            report.update(canary(node))
        elif args.mode == "inspect":
            report.update(inspect(node))
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("nodekit_awg_lifecycle_error=" + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
