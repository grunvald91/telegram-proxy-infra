#!/usr/bin/env python3
"""Stage verified Xray/CoreDNS binaries and inactive Ubuntu Nginx/WireGuard.

Never starts listeners, edits firewall, provisions users or publishes a node.
Designed solely for a fresh, staged and identity-initialized Nodekit VPS.
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
import tarfile
import tempfile
import urllib.request
import urllib.error
import zipfile

ROOT = Path("/var/lib/mnebyvpn-nodekit")
NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
PACKAGES = ("nginx", "libnginx-mod-stream", "wireguard-tools")
ASSETS = {
    "x86_64": {
        "xray": ("https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip",
                 "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82", "zip", "/opt/xray/xray"),
        "coredns": ("https://github.com/coredns/coredns/releases/download/v1.15.0/coredns_1.15.0_linux_amd64.tgz",
                    "2495c5b8f3fab6d0a336c397f1227b75406d86e6ec7125744a29df9e936ab8cd", "tgz", "/opt/coredns/coredns"),
    },
    "aarch64": {
        "xray": ("https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm64-v8a.zip",
                 "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be", "zip", "/opt/xray/xray"),
        "coredns": ("https://github.com/coredns/coredns/releases/download/v1.15.0/coredns_1.15.0_linux_arm64.tgz",
                    "73a5bf107c9791d57741ccd59ad138ab00bcd5bb3f62e2e28c999f5c047334a4", "tgz", "/opt/coredns/coredns"),
    },
}
MAX_ARCHIVE = 48 * 1024 * 1024
MAX_BINARY = 150 * 1024 * 1024

class InstallError(ValueError):
    pass

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_dir(path: Path, *, private: bool = True) -> None:
    if path.is_symlink() or not path.is_dir():
        raise InstallError("Missing or symlinked required directory")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & (0o077 if private else 0o022):
        raise InstallError("Unsafe directory owner or permissions")

def safe_manifest(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise InstallError("Missing or symlinked manifest")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & 0o077 or s.st_size > 10000:
        raise InstallError("Unsafe manifest permissions or size")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise InstallError("Invalid manifest type")
    return value

def node_ready(root: Path, name: str, *, allow_production: bool = False) -> Path:
    if not NODE.fullmatch(name) or name.endswith("-"):
        raise InstallError("Invalid node ID")
    safe_dir(root)
    node = root / name
    safe_dir(node)
    m = safe_manifest(node / "manifest.json")
    # Existing installers remain strict: allow_production defaults to False.
    # Only AWG's systemd *validate* command may request the production shape;
    # it must also independently verify the RU188 Ed25519 approval.
    is_staged = (m.get("state") == "testing" and
                 m.get("activation_enabled") is False and
                 m.get("registration_enabled") is False)
    is_production = (allow_production is True and name == "fi-test-01" and
                     m.get("state") == "active" and
                     m.get("activation_enabled") is True and
                     m.get("registration_enabled") is True)
    roles = m.get("roles")
    if (m.get("node_id") != name or not (is_staged or is_production) or
            not isinstance(roles, list) or
            not {"vpn", "dns", "sni-proxy", "tunnel"}.issubset(set(roles))):
        raise InstallError("Unapproved node state or missing roles")
    identity = node / "identity"
    safe_dir(identity)
    for key in ("node-private.pk8", "node-public.spki"):
        p = identity / key
        if (p.is_symlink() or not p.is_file() or p.stat().st_uid != 0 or
                p.stat().st_mode & 0o077 or not 32 <= p.stat().st_size <= 256):
            raise InstallError("Missing isolated node identity")
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=ubuntu$', release, re.M) or not re.search(
            r'^VERSION_ID="?24\.04"?$', release, re.M):
        raise InstallError("Supports Ubuntu 24.04 only")
    if os.uname().machine not in ASSETS:
        raise InstallError("Unsupported CPU")
    if shutil.disk_usage("/").free < 2 * 1024**3:
        raise InstallError("Less than 2 GiB free")
    return node

def call(cmd: list[str], *, timeout: int = 30, env=None, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True,
                          timeout=timeout, env=env)

def nginx_must_be_inactive(runner=call) -> None:
    if runner(["systemctl", "is-active", "--quiet", "nginx.service"], check=False).returncode == 0:
        raise InstallError("Existing nginx is running")

def download(url: str, sha: str, path: Path, *, opener=None) -> None:
    if not url.startswith("https://github.com/") or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise InstallError("Unpinned release URL")
    opener = opener or urllib.request.urlopen
    h = hashlib.sha256()
    count = 0
    request = urllib.request.Request(url, headers={"User-Agent": "MNEBYVPN-Nodekit/1"})
    try:
        with opener(request, timeout=45) as remote, path.open("xb") as f:
            while chunk := remote.read(1048576):
                count += len(chunk)
                if count > MAX_ARCHIVE:
                    raise InstallError("Release archive too large")
                h.update(chunk)
                f.write(chunk)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if count < 10000 or h.hexdigest() != sha:
        path.unlink(missing_ok=True)
        raise InstallError("Release SHA-256 mismatch")

def unpack(archive: Path, fmt: str, member_name: str, target: Path) -> str:
    with target.open("xb") as f:
        if fmt == "zip":
            with zipfile.ZipFile(archive) as z:
                member = z.getinfo(member_name)
                if member.is_dir() or not 10000 <= member.file_size <= MAX_BINARY:
                    raise InstallError("Invalid zip member")
                with z.open(member) as source:
                    limited_copy(source, f, member.file_size)
        elif fmt == "tgz":
            with tarfile.open(archive, "r:gz") as tar:
                member = tar.getmember(member_name)
                if not member.isfile() or not 10000 <= member.size <= MAX_BINARY:
                    raise InstallError("Invalid tar member")
                with tar.extractfile(member) as source:
                    limited_copy(source, f, member.size)
        else:
            raise InstallError("Unsupported archive")
        f.flush()
        os.fsync(f.fileno())
    return digest(target)

def limited_copy(source, target, amount: int) -> None:
    while amount:
        chunk = source.read(min(amount, 1048576))
        if not chunk:
            raise InstallError("Archive member is truncated")
        target.write(chunk)
        amount -= len(chunk)

def install_binary(src: Path, dest: Path, sha: str) -> None:
    parent = dest.parent
    if parent.is_symlink():
        raise InstallError("Symlink binary directory")
    parent.mkdir(mode=0o755, exist_ok=True)
    safe_dir(parent, private=False)
    if dest.is_symlink():
        raise InstallError("Symlink target")
    if dest.exists():
        s = dest.stat()
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or
                s.st_mode & 0o022 or digest(dest) != sha):
            raise InstallError("Existing executable differs; no overwrite")
        return
    fd, tmp = tempfile.mkstemp(prefix=".nodekit-", dir=parent)
    try:
        os.fchmod(fd, 0o755)
        with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
            shutil.copyfileobj(inp, out, length=1048576)
            out.flush()
            os.fsync(out.fileno())
        if digest(Path(tmp)) != sha:
            raise InstallError("Staged binary changed")
        os.link(tmp, dest, follow_symlinks=False)
    finally:
        Path(tmp).unlink(missing_ok=True)

def install_apt(*, runner=call, policy: Path = Path("/usr/sbin/policy-rc.d")) -> dict:
    # On a fresh VPS the policy file is absent. Never replace an existing one.
    fd = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("#!/bin/sh\nexit 101\n")
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")
        runner(["apt-get", "update", "-qq"], timeout=240, env=env)
        runner(["apt-get", "install", "-y", "-qq", "--no-install-recommends", *PACKAGES],
               timeout=360, env=env)
    finally:
        policy.unlink(missing_ok=True)
    runner(["systemctl", "disable", "--now", "nginx.service"])
    nginx_must_be_inactive(runner)
    if runner(["systemctl", "is-enabled", "--quiet", "nginx.service"],
              check=False).returncode == 0:
        raise InstallError("nginx must remain disabled")
    versions = {}
    for name in PACKAGES:
        # Avoid shell and JS template syntax in the literal argument.
        out = runner(["dpkg-query", "-W", "-f=$" + "{Version}", name])
        versions[name] = out.stdout.strip()
        if not versions[name]:
            raise InstallError("Empty dpkg version")
    return versions

def stage(node: Path, *, runner=call, downloader=download, apt=install_apt) -> dict:
    nginx_must_be_inactive(runner)
    assets = ASSETS[os.uname().machine]
    manifest = node / "components-manifest.json"
    if manifest.exists() or manifest.is_symlink():
        old = safe_manifest(manifest)
        if (old.get("node_id") != node.name or old.get("activation_enabled") is not False
                or set(old.get("binaries", {})) != set(assets)):
            raise InstallError("Existing component record invalid")
        for name, meta in old["binaries"].items():
            path = Path(assets[name][3])
            if (not path.is_file() or path.is_symlink() or
                    digest(path) != meta.get("sha256") or
                    meta.get("archive_sha256") != assets[name][1]):
                raise InstallError("Component integrity drift")
        return dict(old, already_installed=True)

    records = {}
    with tempfile.TemporaryDirectory(prefix=".components-", dir=node) as scratch:
        work = Path(scratch)
        for name, (url, sha, fmt, destination) in assets.items():
            archive, binary = work / (name + ".archive"), work / (name + ".binary")
            downloader(url, sha, archive)
            binary_sha = unpack(archive, fmt, name, binary)
            records[name] = {"sha256": binary_sha, "archive_sha256": sha,
                             "version": "26.11.9" if name == "xray" else "1.15.0",
                             "path": destination}
        versions = apt(runner=runner)
        for name, item in records.items():
            install_binary(work / (name + ".binary"), Path(item["path"]), item["sha256"])
    result = {"schema_version": 1, "node_id": node.name,
              "state": "components_staged", "binaries": records,
              "distro_packages": versions, "activation_enabled": False,
              "registration_enabled": False, "subscribers_enabled": False}
    fd, tmp = tempfile.mkstemp(prefix=".components-manifest-", dir=node)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(result, f, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp, manifest, follow_symlinks=False)
    finally:
        Path(tmp).unlink(missing_ok=True)
    return result

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id", required=True)
    p.add_argument("--stage-root", type=Path, default=ROOT)
    p.add_argument("--mode", choices=("check", "install"), default="check")
    args = p.parse_args()
    try:
        if os.geteuid() != 0:
            raise InstallError("Root required")
        node = node_ready(args.stage_root, args.node_id)
        nginx_must_be_inactive()
        result = ({"node_id": node.name, "ready": True, "activation_enabled": False}
                  if args.mode == "check" else stage(node))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError,
            urllib.error.URLError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print("nodekit_components_error=" + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
