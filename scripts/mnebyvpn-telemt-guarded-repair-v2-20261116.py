#!/usr/bin/env python3
"""Guarded, reversible migration of direct-ozon Telemt config to a writable
per-service directory. Never edits the other Telemt services or listeners.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

SERVICE = "telemt-direct-ozon"
ORIGINAL = Path("/etc/telemt/direct-ozon.toml")
TARGET_DIR = Path("/opt/telemt-direct-ozon/mnebyvpn-api-managed-v2")
TARGET = TARGET_DIR / "config.toml"
DROPIN = Path("/etc/systemd/system/telemt-direct-ozon.service.d/91-mnebyvpn-managed-v2.conf")
API = "http://127.0.0.1:9096"
EXPECTED_COMMAND = "/usr/bin/telemt --silent /etc/telemt/direct-ozon.toml"


def call(cmd, *, check=True):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    if check and proc.returncode:
        raise RuntimeError("Failed: " + cmd[0] + " (" + str(proc.returncode) + ")")
    return proc


def request(method, path, payload=None, token=""):
    headers = {"Authorization": token} if token else {}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        API + path, headers=headers, method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=7) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as error:
        try:
            value = json.loads(error.read(2048))
        except Exception:
            value = {}
        return error.code, value


def healthy():
    for _ in range(28):
        if call(["systemctl", "is-active", "--quiet", SERVICE], check=False).returncode == 0:
            try:
                status, body = request("GET", "/v1/health")
                if status == 200 and body.get("ok") is True:
                    return True
            except Exception:
                pass
        time.sleep(0.5)
    return False


def user_ids(token):
    code, data = request("GET", "/v1/users", token=token)
    if code != 200 or data.get("ok") is not True or not isinstance(data.get("data"), list):
        raise RuntimeError("Telemt user inventory unavailable")
    return {entry["username"] for entry in data["data"]}


def main():
    if os.getuid() != 0:
        raise RuntimeError("Root required")
    if not healthy():
        raise RuntimeError("Existing service unhealthy: abort before edits")
    if not ORIGINAL.is_file() or ORIGINAL.is_symlink() or DROPIN.exists() or TARGET_DIR.exists():
        raise RuntimeError("Unexpected configuration state: abort")
    # Protect against modifying a changed or customized systemd service.
    unit = call(["systemctl", "cat", SERVICE]).stdout
    starts = re.findall(r"(?m)^ExecStart=(.+)$", unit)
    if starts != [EXPECTED_COMMAND]:
        raise RuntimeError("Unexpected ExecStart: abort")
    original_bytes = ORIGINAL.read_bytes()
    if not 0 < len(original_bytes) < 1024 * 1024:
        raise RuntimeError("Unexpected original file size")
    # Reject relative includes/paths whose resolution could change after relocation.
    for line in original_bytes.decode().splitlines():
        match = re.match(r"\s*([A-Za-z0-9_]+(?:_path|_file|_dir))\s*=\s*['\"]([^'\"]+)['\"]", line)
        if match and not match.group(2).startswith("/"):
            raise RuntimeError("Relative path in config: relocation not proven")
    match = re.search(r'(?m)^\s*auth_header\s*=\s*("(?:[^"\\]|\\.)*")', original_bytes.decode())
    token = json.loads(match.group(1)) if match else ""
    baseline = user_ids(token)
    print("PREFLIGHT_ACTIVE=true")
    print("PREFLIGHT_EXISTING_USERS=" + str(len(baseline)))
    account = pwd.getpwnam("telemt")
    backup = Path("/root/direct-ozon.pre-mnebyvpn-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".toml")
    if backup.exists():
        raise RuntimeError("Backup path already exists")
    with backup.open("xb") as handle:
        handle.write(original_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    backup.chmod(0o600)
    TARGET_DIR.mkdir(mode=0o700, parents=False)
    os.chown(TARGET_DIR, account.pw_uid, account.pw_gid)
    temp = TARGET_DIR / ".config.toml.tmp"
    with temp.open("xb") as handle:
        handle.write(original_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(temp, account.pw_uid, account.pw_gid)
    temp.chmod(0o600)
    os.replace(temp, TARGET)
    if hashlib.sha256(TARGET.read_bytes()).digest() != hashlib.sha256(original_bytes).digest():
        raise RuntimeError("File-copy integrity failed")
    DROPIN.parent.mkdir(parents=True, exist_ok=True)
    DROPIN.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/telemt --silent " + str(TARGET) + "\n")
    DROPIN.chmod(0o644)

    try:
        call(["systemctl", "daemon-reload"])
        call(["systemctl", "restart", SERVICE])
        if not healthy():
            raise RuntimeError("New instance not healthy")
        if user_ids(token) != baseline:
            raise RuntimeError("Pre-existing user identities changed")
        print("MANAGED_CONFIG_RUNNING=true")

        name = "dns_" + secrets.token_hex(12)
        secret = secrets.token_hex(16)
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        success = False
        try:
            status, data = request("POST", "/v1/users", {
                "username": name, "secret": secret, "enabled": True,
                "expiration_rfc3339": expires,
            }, token)
            print("CREATE_HTTP=" + str(status))
            if status not in (201, 202) or data.get("ok") is not True:
                error = data.get("error")
                print("CREATE_ERROR_TYPE=" + (str(error.get("code", "unknown")) if isinstance(error, dict) else "unknown"))
                raise RuntimeError("Create failed")
            info = data.get("data")
            if not isinstance(info, dict) or info.get("secret") != secret:
                raise RuntimeError("Create did not return matching secret")
            for _ in range(15):
                get_code, obj = request("GET", "/v1/users/" + name, token=token)
                info = obj.get("data", {})
                if get_code == 200 and isinstance(info, dict) and info.get("enabled") is True:
                    success = True
                    break
                time.sleep(0.4)
            if not success:
                raise RuntimeError("Persisted enabled user unavailable")
            print("CREATE_PERSISTED_ENABLED=true")
            print("CREATE_IN_RUNTIME=" + str(info.get("in_runtime")).lower())
            status, _ = request("POST", "/v1/users/" + name + "/disable", token=token)
            if status not in (200, 202):
                raise RuntimeError("Disable rejected")
            status, state = request("GET", "/v1/users/" + name, token=token)
            if status != 200 or state.get("data", {}).get("enabled") is not False:
                raise RuntimeError("Disable unverified")
            print("DISABLE_VERIFIED=true")
        finally:
            get_code, _ = request("GET", "/v1/users/" + name, token=token)
            if get_code == 200:
                request("POST", "/v1/users/" + name + "/disable", token=token)
                request("DELETE", "/v1/users/" + name, token=token)
            get_code, _ = request("GET", "/v1/users/" + name, token=token)
            if get_code != 404:
                raise RuntimeError("Canary cleanup unverified")
        if user_ids(token) != baseline:
            raise RuntimeError("Existing user inventory differs after canary")
        if not healthy():
            raise RuntimeError("Health regressed")
        print("TELEMT_API_MUTATIONS_WORK=true")
        print("TELEMT_CLIENT_HANDSHAKE_UNVERIFIED=true")
        print("EXISTING_USERS_PRESERVED=true")
        print("BACKUP_EXISTS=true")
    except BaseException:
        print("ROLLBACK_BEGIN=true")
        DROPIN.unlink(missing_ok=True)
        call(["systemctl", "daemon-reload"], check=False)
        call(["systemctl", "restart", SERVICE], check=False)
        print("ROLLBACK_HEALTH=" + str(healthy()).lower())
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("RELEASE_FAILED=" + type(exc).__name__ + ": " + str(exc)[:150])
        sys.exit(1)
