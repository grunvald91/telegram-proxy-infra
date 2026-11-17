#!/usr/bin/env python3
"""Safely install the *isolated* Nodekit VPN supervisor on a NEW VPS.

Modes: install (does not start or enable) and canary (starts EMPTY service,
never enables on boot). No Xray download, network config or subscriber grants.
Every existing file is immutable unless byte-for-byte identical.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import time

from vpn_stage import _hash_binary, _private_dir
from vpn_supervisor import child_can_execute, locked_json, PUBLIC_KEY_PREFIX

NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}")
FILES = ("vpn_stage.py", "vpn_supervisor.py", "forward_command.py")
SERVICE_USER = "mnebyvpn-nodekit-xray"
DEFAULT_ROOT = Path("/var/lib/mnebyvpn-nodekit")
DEFAULT_INSTALL = Path("/opt/mnebyvpn-nodekit")
DEFAULT_UNIT = Path("/etc/systemd/system/mnebyvpn-nodekit-vpn@.service")
SOURCE_UNIT = "mnebyvpn-nodekit-vpn@.service.example"
PROTECTED_IPS = ("89.125.90.101", "188.120.254.223")


class InstallError(ValueError):
    pass


def secure_dir(path: Path, *, root: bool, private: bool = False) -> None:
    if path.is_symlink() or not path.is_dir():
        raise InstallError("Required non-symlink directory missing")
    st = path.stat()
    if (root and st.st_uid != 0) or st.st_mode & (0o077 if private else 0o022):
        raise InstallError("Unsafe directory ownership/permissions")


def safe_source(path: Path, *, root: bool, max_size: int = 150_000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise InstallError("Untrusted source file")
    st = path.stat()
    if ((root and st.st_uid != 0) or st.st_mode & 0o022 or
            st.st_size < 16 or st.st_size > max_size):
        raise InstallError("Unsafe source permissions, owner or size")
    return path.read_bytes()


def exclusive_file(path: Path, content: bytes, mode: int, *, owner_uid: int = 0) -> bool:
    """Write only on first install. Refuse modification even during races."""
    if path.is_symlink():
        raise InstallError("Destination symlink refused")
    if path.exists():
        st = path.stat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid or
                st.st_mode & 0o777 != mode or path.read_bytes() != content):
            raise InstallError("Existing installation differs; explicit upgrade required")
        return False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return True


def root_user(*, root: bool, runner) -> tuple[int, int]:
    try:
        user = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        if not root:
            raise InstallError("Isolated service user not installed")
        runner(["useradd", "--system", "--user-group", "--no-create-home",
                "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
                SERVICE_USER], check=True, timeout=10, capture_output=True)
        user = pwd.getpwnam(SERVICE_USER)
    if (user.pw_uid == 0 or user.pw_gid == 0 or
            user.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")):
        raise InstallError("Xray service identity must be nonroot and no-login")
    return user.pw_uid, user.pw_gid


def validate_stage(stage_root: Path, node_id: str, xray: Path, digest: str,
                   controller_source: Path, pub_digest: str,
                   *, root: bool = True) -> bytes:
    if (not isinstance(node_id, str) or not NODE.fullmatch(node_id) or
            node_id.endswith("-") or not re.fullmatch(r"[0-9a-f]{64}", digest) or
            not re.fullmatch(r"[0-9a-f]{64}", pub_digest)):
        raise InstallError("Invalid Nodekit ID or digest pin")
    secure_dir(stage_root, root=root, private=True)
    node = stage_root / node_id
    secure_dir(node, root=root, private=True)
    secure_dir(node / "vpn", root=root, private=True)
    manifest = locked_json(node / "manifest.json", 4096)
    stage = locked_json(node / "vpn" / "vpn-stage-manifest.json", 4096)
    template = locked_json(node / "vpn" / "xray-config.json", 32768)
    if (manifest.get("node_id") != node_id or
            manifest.get("state") != "testing" or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False or
            "vpn" not in manifest.get("roles", []) or
            stage.get("node_id") != node_id or
            stage.get("state") != "staged" or
            stage.get("vpn_users_enabled") is not False or
            stage.get("activation_enabled") is not False or
            stage.get("controller_enrolled") is not False or
            stage.get("independent_e2e_verified") is not False or
            stage.get("vpn_port") != manifest.get("listeners", {}).get("vpn_tcp") or
            not isinstance(template, dict) or
            not isinstance(template.get("inbounds"), list) or
            len(template["inbounds"]) != 1 or
            not isinstance(template["inbounds"][0], dict) or
            template["inbounds"][0].get("port") != stage.get("vpn_port") or
            template["inbounds"][0].get("protocol") != "vless" or
            template["inbounds"][0].get("settings", {}).get("clients") != [] or
            template["inbounds"][0].get("streamSettings", {}).get("security") != "reality"):
        raise InstallError("Only untouched, unpublished Xray stage may be installed")
    if _hash_binary(xray, root) != digest or stage.get("xray_sha256") != digest:
        raise InstallError("Xray binary differs from the staged, pinned hash")
    existing_state = node / "vpn" / "access-state.json"
    if existing_state.exists() or existing_state.is_symlink():
        if locked_json(existing_state, 2_000_000) != {}:
            raise InstallError("Never install a testing canary over existing clients")
    pub = safe_source(controller_source, root=root, max_size=44)
    if (len(pub) != 44 or not pub.startswith(PUBLIC_KEY_PREFIX) or
            hashlib.sha256(pub).hexdigest() != pub_digest):
        raise InstallError("Controller Ed25519 SPKI does not match independent pin")
    return pub


def install(node_id: str, source_dir: Path, controller_source: Path,
            xray: Path, xray_sha256: str, controller_pub_sha256: str, *,
            stage_root: Path = DEFAULT_ROOT,
            install_dir: Path = DEFAULT_INSTALL,
            unit_file: Path = DEFAULT_UNIT,
            mode: str = "install", require_root: bool = True,
            runner=subprocess.run, service_identity=None,
            check_canary=None) -> dict:
    if mode not in ("install", "canary"):
        raise InstallError("Unknown safe install mode")
    if require_root and os.geteuid() != 0:
        raise InstallError("Root required for new VPS service installer")
    secure_dir(source_dir, root=require_root, private=True)
    pub = validate_stage(stage_root, node_id, xray, xray_sha256,
                         controller_source, controller_pub_sha256,
                         root=require_root)
    sources = {filename: safe_source(source_dir / filename,
                                    root=require_root) for filename in FILES}
    unit = safe_source(source_dir / SOURCE_UNIT, root=require_root)
    if (b"KillMode=control-group" not in unit or
            b"Restart=on-failure" not in unit or
            b"NoNewPrivileges=yes" not in unit or
            b"/opt/mnebyvpn-nodekit/vpn_supervisor.py" not in unit or
            b"ExecStart=" not in unit):
        raise InstallError("Unreviewed or unsafe systemd service definition")
    uid, gid = service_identity() if service_identity else root_user(
        root=require_root, runner=runner)
    if require_root and not child_can_execute(xray, uid, gid):
        raise InstallError("Dedicated Xray user cannot execute pinned binary")
    # Existing install path is immutable; upgrades use a separately audited PR.
    created_files: list[Path] = []
    created_dir = False
    owner_uid = 0 if require_root else os.geteuid()
    service = f"mnebyvpn-nodekit-vpn@{node_id}.service"
    started = False
    try:
        if install_dir.is_symlink():
            raise InstallError("Install root symlink forbidden")
        if not install_dir.exists():
            install_dir.mkdir(mode=0o755)
            created_dir = True
        secure_dir(install_dir, root=require_root)
        for filename, payload in sources.items():
            path = install_dir / filename
            if exclusive_file(path, payload, 0o644, owner_uid=owner_uid):
                created_files.append(path)
        pub_path = stage_root / node_id / "controller-access.spki"
        if exclusive_file(pub_path, pub, 0o600, owner_uid=owner_uid):
            created_files.append(pub_path)
        secure_dir(unit_file.parent, root=require_root)
        if exclusive_file(unit_file, unit, 0o644, owner_uid=owner_uid):
            created_files.append(unit_file)
        runner(["systemctl", "daemon-reload"], check=True, timeout=12,
               capture_output=True)
        if mode == "canary":
            # Refuse altering a pre-existing running service or subscriber pool.
            existing = runner(["systemctl", "is-active", "--quiet", service],
                              check=False, timeout=6, capture_output=True)
            if existing.returncode == 0:
                raise InstallError("Already active canary needs independent audit")
            # Start can fail after partially launching a unit. Always stop
            # this just-attempted service before rolling back new files.
            started = True
            runner(["systemctl", "start", service], check=True, timeout=20,
                   capture_output=True)
            runner(["systemctl", "is-active", "--quiet", service], check=True,
                   timeout=6, capture_output=True)
            socket_path = Path("/run/mnebyvpn-nodekit") / node_id / "control.sock"
            if check_canary is not None:
                if not check_canary(socket_path):
                    raise InstallError("Canary local supervisor socket unavailable")
            else:
                for _ in range(30):
                    if (socket_path.is_socket() and not socket_path.is_symlink() and
                            socket_path.stat().st_uid == 0 and
                            socket_path.stat().st_mode & 0o777 == 0o600):
                        break
                    time.sleep(0.1)
                else:
                    raise InstallError("Canary local supervisor socket unavailable")
        return {"node_id": node_id, "installed": True,
                "canary_started": mode == "canary",
                "published": False, "subscriber_access_enabled": False}
    except BaseException:
        if started:
            runner(["systemctl", "stop", service], check=False,
                   timeout=12, capture_output=True)
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        if created_dir:
            try:
                install_dir.rmdir()
            except OSError:
                pass
        if unit_file in created_files:
            runner(["systemctl", "daemon-reload"], check=False,
                   timeout=12, capture_output=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node-id", required=True)
    ap.add_argument("--source-dir", type=Path, required=True)
    ap.add_argument("--controller-public", type=Path, required=True)
    ap.add_argument("--controller-public-sha256", required=True)
    ap.add_argument("--xray", type=Path, default=Path("/opt/xray/xray"))
    ap.add_argument("--xray-sha256", required=True)
    ap.add_argument("--mode", choices=("install", "canary"), default="install")
    args = ap.parse_args()
    try:
        result = install(
            args.node_id, args.source_dir, args.controller_public,
            args.xray, args.xray_sha256, args.controller_public_sha256,
            mode=args.mode)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError):
        # Do not print paths, public-key text, raw exceptions, credentials.
        print("nodekit_install_error=FAIL_CLOSED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
