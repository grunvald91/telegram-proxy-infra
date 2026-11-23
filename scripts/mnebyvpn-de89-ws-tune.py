#!/usr/bin/env python3
"""Guarded DE89 Nginx WebSocket latency/buffering fix for /mnebyvpn-vpn/ws.

Adds unbuffered streaming and TCP_NODELAY/keepalive inside the isolated
`location = /mnebyvpn-vpn/ws` block without touching webhook, /sub, or :443.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

DEFAULT_SITE = pathlib.Path("/etc/nginx/sites-available/mnebyvpn-telegram-8443.conf")
DEFAULT_BACKUP_ROOT = pathlib.Path("/opt/mnebyvpn/backups")
WS_BLOCK_RE = re.compile(
    r"(?P<header>[ \t]*location\s*=\s*/mnebyvpn-vpn/ws\s*\{)(?P<body>[^}]*)(?P<footer>\})",
    re.DOTALL,
)
REQUIRED_DIRECTIVES = (
    ("proxy_buffering", "proxy_buffering off;"),
    ("proxy_request_buffering", "proxy_request_buffering off;"),
    ("tcp_nodelay", "tcp_nodelay on;"),
    ("proxy_socket_keepalive", "proxy_socket_keepalive on;"),
)


class TuneError(RuntimeError):
    pass


def render_ws_tune(source: str) -> tuple[str, bool]:
    matches = list(WS_BLOCK_RE.finditer(source))
    if len(matches) != 1:
        raise TuneError("Expected exactly one `location = /mnebyvpn-vpn/ws` block")
    match = matches[0]
    body = match.group("body")
    if "proxy_pass http://127.0.0.1:18943;" not in body:
        raise TuneError("Unexpected /mnebyvpn-vpn/ws upstream target")

    indent = "        "
    for line in body.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            indent = line[: len(line) - len(line.lstrip(" \t"))]
            break

    additions: list[str] = []
    for key, directive in REQUIRED_DIRECTIVES:
        if re.search(rf"(?m)^\s*{re.escape(key)}\b", body):
            if directive not in body:
                raise TuneError(f"Conflicting existing directive for {key}")
        else:
            additions.append(f"{indent}{directive}")

    if not additions:
        return source, False

    newline_body = body.rstrip(" \t")
    if not newline_body.endswith("\n"):
        newline_body += "\n"
    closing_indent = match.group("header")[: len(match.group("header")) - len(match.group("header").lstrip(" \t"))]
    updated_block = (
        match.group("header")
        + newline_body
        + "\n".join(additions)
        + "\n"
        + closing_indent
        + match.group("footer")
    )
    return source[: match.start()] + updated_block + source[match.end() :], True


def atomic_write(path: pathlib.Path, content: str) -> None:
    st = path.stat()
    fd, tmp_name = tempfile.mkstemp(prefix=".mnebyvpn-ws-tune-", dir=str(path.parent))
    try:
        os.fchmod(fd, st.st_mode & 0o7777)
        os.fchown(fd, st.st_uid, st.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def run_cmd(*args: str, timeout: int = 12) -> None:
    res = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        raise TuneError(f"Command failed: {' '.join(args[:2])}: {res.stderr.strip()[:200]}")


def verify_live_health() -> None:
    run_cmd("nginx", "-t")
    listeners = subprocess.run(
        ["ss", "-H", "-lnt"], capture_output=True, text=True, timeout=8, check=True
    ).stdout
    if not any(line.split()[3] == "127.0.0.1:18943" for line in listeners.splitlines() if len(line.split()) >= 4):
        raise TuneError("127.0.0.1:18943 xray listener missing")
    code = subprocess.run(
        [
            "curl", "--noproxy", "*", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "6", "--resolve", "cdn.servgo.ru:8443:127.0.0.1",
            "-X", "POST", "-H", "Content-Type: application/json", "-d", '{"update_id":1}',
            "https://cdn.servgo.ru:8443/mnebyvpn-telegram/webhook",
        ],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip()
    if code != "401":
        raise TuneError(f"Unexpected webhook status on 8443: {code}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("dry-run", "apply", "rollback"), default="dry-run")
    parser.add_argument("--site", type=pathlib.Path, default=DEFAULT_SITE)
    parser.add_argument("--backup-dir", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)

    if not args.site.is_file() or args.site.is_symlink():
        raise TuneError("Target nginx site config missing or unsafe")

    current = args.site.read_text(encoding="utf-8")
    if args.mode == "dry-run":
        updated, changed = render_ws_tune(current)
        print(f"ws_tune_changed={str(changed).lower()}")
        print(f"ws_tune_sha256={hashlib.sha256(updated.encode('utf-8')).hexdigest()}")
        return 0

    if os.geteuid() != 0:
        raise TuneError("Live apply/rollback requires root")

    if args.mode == "rollback":
        if args.backup_dir is None or not (args.backup_dir / "original.conf").is_file():
            raise TuneError("Valid --backup-dir with original.conf required for rollback")
        atomic_write(args.site, (args.backup_dir / "original.conf").read_text(encoding="utf-8"))
        run_cmd("nginx", "-t")
        run_cmd("systemctl", "reload", "nginx")
        verify_live_health()
        print("ws_tune_rolled_back=true")
        return 0

    updated, changed = render_ws_tune(current)
    if not changed:
        verify_live_health()
        print("ws_tune_already_present=true")
        return 0

    backup_dir = args.backup_dir or (DEFAULT_BACKUP_ROOT / f"ws-tune-{int(time.time())}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    backup_file = backup_dir / "original.conf"
    if not backup_file.exists():
        backup_file.write_text(current, encoding="utf-8")
        os.chmod(backup_file, 0o600)

    try:
        atomic_write(args.site, updated)
        run_cmd("nginx", "-t")
        run_cmd("systemctl", "reload", "nginx")
        verify_live_health()
    except Exception:
        atomic_write(args.site, current)
        subprocess.run(["nginx", "-t"], capture_output=True, timeout=8)
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=12)
        raise

    print(f"ws_tune_applied=true")
    print(f"ws_tune_backup_dir={backup_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TuneError as exc:
        print(f"ws_tune_error={exc}", file=sys.stderr)
        raise SystemExit(2)
