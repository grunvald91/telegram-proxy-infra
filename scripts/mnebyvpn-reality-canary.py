#!/usr/bin/env python3
"""Temporary loopback-only REALITY/Vision latency probe.

Only for comparative diagnostics. Never opens a public port or changes the
production Xray, VPN provisioner, Nginx, firewall, or subscriber credentials.
The transient systemd unit expires automatically; explicit cleanup removes
the temporary configuration, including the REALITY private key.
"""
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path("/run/mnebyvpn-reality-latency-canary")
CONF = ROOT / "config.json"
XRAY = "/opt/xray/xray"
UNIT = "mnebyvpn-reality-latency-canary.service"
PORT = 18948


def run(args, *, timeout=15, check=True):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout, check=check)


def cleanup():
    run(["systemctl", "stop", UNIT], check=False)
    run(["systemctl", "reset-failed", UNIT], check=False)
    if ROOT.is_dir() and not ROOT.is_symlink():
        shutil.rmtree(ROOT)
    print("reality_canary_cleanup=complete")


def setup():
    if os.geteuid() != 0:
        raise SystemExit("root_required")
    if not pathlib.Path(XRAY).is_file():
        raise SystemExit("xray_missing")
    if ROOT.exists():
        raise SystemExit("canary_already_exists")
    for service in ("xray.service", "mnebyvpn-vpn-provisioner.service"):
        if run(["systemctl", "is-active", service], check=False).stdout.strip() != "active":
            raise SystemExit("preexisting_service_unhealthy")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if sock.connect_ex(("127.0.0.1", PORT)) == 0:
            raise SystemExit("canary_port_busy")
    output = run([XRAY, "x25519"])
    keys = output.stdout + "\n" + output.stderr
    private_match = re.search(r"(?im)^\s*private\s*key\s*:\s*(\S+)", keys)
    public_match = re.search(r"(?im)^\s*(?:public\s*key|password)\s*:\s*(\S+)", keys)
    if not private_match or not public_match:
        raise SystemExit(f"reality_key_output_unrecognized private={bool(private_match)} public={bool(public_match)} stdout_lines={len(output.stdout.splitlines())} stderr_lines={len(output.stderr.splitlines())}")
    private_key, public_key = private_match.group(1), public_match.group(1)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", private_key) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
        raise SystemExit("invalid_reality_key_format")
    secret_id = str(uuid.uuid4())
    short_id = secrets.token_hex(8)
    source = json.loads(pathlib.Path("/etc/mnebyvpn/xray-canary.json").read_text())
    if not isinstance(source.get("routing"), dict) or not isinstance(source.get("outbounds"), list):
        raise SystemExit("existing_canary_security_policy_missing")
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": PORT, "protocol": "vless",
            "settings": {
                "clients": [{"id": secret_id, "flow": "xtls-rprx-vision"}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": "www.cloudflare.com:443",
                    "xver": 0,
                    "serverNames": ["www.cloudflare.com"],
                    "privateKey": private_key,
                    "shortIds": [short_id],
                },
            },
        }],
        "outbounds": source["outbounds"],
        "routing": source["routing"],
    }
    ROOT.mkdir(mode=0o700)
    os.chmod(ROOT, 0o700)
    CONF.write_text(json.dumps(config))
    os.chmod(CONF, 0o600)
    run([XRAY, "run", "-test", "-config", str(CONF)])
    run([
        "systemd-run", "--quiet", "--collect",
        "--unit=mnebyvpn-reality-latency-canary",
        "--property=RuntimeMaxSec=210",
        "--property=MemoryMax=256M",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectHome=yes",
        "--property=ProtectSystem=strict",
        "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        XRAY, "run", "-config", str(CONF),
    ])
    for _ in range(30):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(.2)
            if sock.connect_ex(("127.0.0.1", PORT)) == 0:
                print(json.dumps({
                    "credential": secret_id,
                    "password": public_key,
                    "shortId": short_id,
                    "port": PORT,
                    "sni": "www.cloudflare.com",
                    "canary_localhost_only": True,
                }))
                return
        time.sleep(.1)
    raise SystemExit("canary_listener_failed")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("setup", "cleanup"):
        raise SystemExit("usage: setup|cleanup")
    if sys.argv[1] == "cleanup":
        cleanup()
    else:
        try:
            setup()
        except BaseException:
            cleanup()
            raise
