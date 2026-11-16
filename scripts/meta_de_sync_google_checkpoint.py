#!/usr/bin/env python3
"""Safely promote DE stable checkpoint ONLY when live Corefile differs solely
by the verified Google RU ingress block (# Verified Google RU ingress 20261116).

Fails closed on any unexpected Corefile, nginx.conf, proxy.stable, or backup drift.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

CHECKPOINT_POINTER = Path("/opt/mnebydns-stable-checkpoints/current")
LIVE_DNS = Path("/opt/mnebydns-dot/Corefile")
LIVE_NGINX = Path("/etc/nginx/nginx.conf")
LIVE_PROXY = Path("/etc/mnebydns-googlepilot/nginx.conf")
BACKUP_COREFILE = Path("/var/backups/mnebydns-google-route-20261116-053515/Corefile")
LOCK_PATH = Path("/run/lock/mnebyvpn-public-route.lock")
DE_STAGE_STATE = Path("/var/lib/mneby-meta-v26-de")
DE_WATCHDOG_TIMER = "mneby-meta-v26-de-watchdog.timer"
GOOGLE_MARKER = "# Verified Google RU ingress 20261116"
GOOGLE_HOSTS = (
    "www.google.com",
    "generativelanguage.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "play.googleapis.com",
    "aicode.googleapis.com",
    "oauth2.googleapis.com",
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(argv: list[str], *, check: bool = True, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{argv[0]} exited with {proc.returncode}: {proc.stderr.strip()}")
    return proc


@contextmanager
def _locked(lock_path: Path):
    lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def parse_manifest(manifest_path: Path) -> list[tuple[str, str]]:
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeError("stable-manifest.sha256 missing or invalid")
    entries: list[tuple[str, str]] = []
    for raw in manifest_path.read_text("utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.fullmatch(r"([0-9a-f]{64})\s{2}([^/\s]+)", line)
        if not m or m.group(2) in (".", ".."):
            raise RuntimeError(f"unexpected manifest entry: {line!r}")
        entries.append((m.group(1), m.group(2)))
    if not entries:
        raise RuntimeError("stable-manifest.sha256 is empty")
    return entries


def verify_manifest(checkpoint_dir: Path) -> list[str]:
    entries = parse_manifest(checkpoint_dir / "stable-manifest.sha256")
    names: list[str] = []
    for expected_hash, name in entries:
        target = checkpoint_dir / name
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f"checkpoint file missing or symlink: {name}")
        actual = _sha256_bytes(target.read_bytes())
        if actual != expected_hash:
            raise RuntimeError(f"checkpoint checksum mismatch for {name}")
        names.append(name)
    if "dns.stable" not in names or "nginx.stable" not in names:
        raise RuntimeError("manifest missing dns.stable or nginx.stable")
    return names


def is_expected_google_suffix(suffix: str) -> bool:
    stripped = suffix.strip("\n")
    lines = stripped.splitlines()
    if len(lines) < 5:
        return False
    if lines[0].strip() != GOOGLE_MARKER:
        return False
    header = lines[1].strip()
    expected_header = " ".join(f"tls://{h}:853" for h in GOOGLE_HOSTS) + " {"
    if header != expected_header:
        return False
    body = "\n".join(lines[1:])
    if "bind 89.125.90.101" not in body:
        return False
    if 'answer "{{ .Name }} 20 IN A 188.120.254.223"' not in body:
        return False
    if "forward . tls://9.9.9.9" not in body:
        return False
    depth = 0
    for idx, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
            if depth == 0 and idx != len(body) - 1:
                return False
    return depth == 0


def sync_google_checkpoint(
    *,
    pointer_path: Path = CHECKPOINT_POINTER,
    live_dns_path: Path = LIVE_DNS,
    live_nginx_path: Path = LIVE_NGINX,
    live_proxy_path: Path = LIVE_PROXY,
    backup_corefile_path: Path = BACKUP_COREFILE,
    lock_path: Path = LOCK_PATH,
    de_stage_state_path: Path = DE_STAGE_STATE,
    check_services: bool = True,
    now_epoch: int | None = None,
) -> str:
    if check_services:
        _run(["systemctl", "is-active", "--quiet", "nginx.service"])
        _run(["systemctl", "is-active", "--quiet", "mnebydns-dot.service"])
        _run(["nginx", "-t"])
        if _run(["systemctl", "is-active", "--quiet", DE_WATCHDOG_TIMER], check=False).returncode == 0:
            raise RuntimeError("active DE experiment watchdog blocks checkpoint update")
    if de_stage_state_path.exists():
        raise RuntimeError("active DE experiment state blocks checkpoint update")

    with _locked(lock_path):
        if not pointer_path.is_file() or pointer_path.is_symlink():
            raise RuntimeError("stable checkpoint pointer missing")
        old_raw = pointer_path.read_text("utf-8").strip()
        base_parent = pointer_path.parent
        old_dir = Path(old_raw)
        if old_dir.parent != base_parent or not re.fullmatch(r"\d+", old_dir.name):
            raise RuntimeError(f"unexpected checkpoint pointer: {old_raw!r}")
        if not old_dir.is_dir() or old_dir.is_symlink():
            raise RuntimeError("current checkpoint directory missing")

        manifest_names = verify_manifest(old_dir)

        live_nginx_bytes = live_nginx_path.read_bytes()
        if (old_dir / "nginx.stable").read_bytes() != live_nginx_bytes:
            raise RuntimeError("DE live nginx.conf differs from stable checkpoint; refusing promotion")
        if "proxy.stable" in manifest_names:
            if not live_proxy_path.is_file() or (old_dir / "proxy.stable").read_bytes() != live_proxy_path.read_bytes():
                raise RuntimeError("DE live proxy nginx.conf differs from stable checkpoint; refusing promotion")

        old_dns_bytes = (old_dir / "dns.stable").read_bytes()
        live_dns_bytes = live_dns_path.read_bytes()
        if old_dns_bytes == live_dns_bytes:
            print("de_checkpoint_already_synced=true", flush=True)
            return str(old_dir)

        if backup_corefile_path.is_file():
            if backup_corefile_path.read_bytes() != old_dns_bytes:
                raise RuntimeError("2026-11-16 Corefile backup differs from old dns.stable; refusing promotion")

        old_dns_text = old_dns_bytes.decode("utf-8")
        live_dns_text = live_dns_bytes.decode("utf-8")
        if not live_dns_text.startswith(old_dns_text):
            raise RuntimeError("live Corefile modified outside appended suffix; refusing promotion")
        suffix = live_dns_text[len(old_dns_text) :]
        if not is_expected_google_suffix(suffix):
            raise RuntimeError("live Corefile diff does not match Verified Google RU ingress 20261116 block")

        ts = int(time.time()) if now_epoch is None else int(now_epoch)
        new_dir = base_parent / str(ts)
        while new_dir.exists():
            ts += 1
            new_dir = base_parent / str(ts)
        new_dir.mkdir(mode=0o700)
        try:
            for item in old_dir.iterdir():
                if item.name == "stable-manifest.sha256" or not item.is_file() or item.is_symlink():
                    continue
                shutil.copy2(item, new_dir / item.name)
            shutil.copyfile(live_dns_path, new_dir / "dns.stable")
            manifest_lines = []
            for name in manifest_names:
                digest = _sha256_bytes((new_dir / name).read_bytes())
                manifest_lines.append(f"{digest}  {name}\n")
            manifest_bytes = "".join(manifest_lines).encode("utf-8")
            mpath = new_dir / "stable-manifest.sha256"
            fd = os.open(mpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(manifest_bytes)
                f.flush()
                os.fsync(f.fileno())
            _fsync_dir(new_dir)
            verify_manifest(new_dir)
            if (new_dir / "dns.stable").read_bytes() != live_dns_bytes:
                raise RuntimeError("promoted dns.stable mismatch")
            if (new_dir / "nginx.stable").read_bytes() != live_nginx_bytes:
                raise RuntimeError("promoted nginx.stable mismatch")

            pointer_mode = pointer_path.stat().st_mode & 0o777
            tmp_pointer = base_parent / f"current.next.{os.getpid()}"
            fd = os.open(tmp_pointer, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, pointer_mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(str(new_dir) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_pointer, pointer_mode)
            os.replace(tmp_pointer, pointer_path)
            _fsync_dir(base_parent)
        except BaseException:
            shutil.rmtree(new_dir, ignore_errors=True)
            raise

        if pointer_path.read_text("utf-8").strip() != str(new_dir):
            raise RuntimeError("failed to verify updated checkpoint pointer")
        print(f"de_checkpoint_promoted={new_dir}", flush=True)
        return str(new_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-service-checks", action="store_true")
    args = parser.parse_args(argv)
    sync_google_checkpoint(check_services=not args.no_service_checks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
