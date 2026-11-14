#!/usr/bin/env python3
"""Read-only public personal DoT certificate monitor, with machine-readable output."""
import datetime as dt
import hashlib
import json
import socket
import ssl
import sys

IP = "89.125.90.101"
NAMES = ("dns.mnebyvpn.site", "aaaaaaaaaaaa.dns.mnebyvpn.site")
WARNING_DAYS = 30
CRITICAL_DAYS = 14

def get_end(name: str):
    ctx = ssl.create_default_context()
    with socket.create_connection((IP, 853), timeout=8) as plain:
        plain.settimeout(8)
        with ctx.wrap_socket(plain, server_hostname=name) as secure:
            cert = secure.getpeercert()
            leaf = secure.getpeercert(binary_form=True)
            if not cert or not leaf:
                raise ValueError("No verified certificate")
            expires = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            expires = expires.replace(tzinfo=dt.timezone.utc)
            return expires, hashlib.sha256(leaf).hexdigest()

def run():
    today = dt.datetime.now(dt.timezone.utc)
    result = {"audited_at": today.isoformat(), "read_only": True}
    try:
        for name in NAMES:
            expires, fingerprint = get_end(name)
            prefix = "legacy" if name.startswith("dns.") else "personal"
            days = (expires - today).total_seconds() // 86400
            result[prefix + "_days_remaining"] = int(days)
            result[prefix + "_sha256"] = fingerprint
            result[prefix + "_expires_utc"] = expires.isoformat()
        personal = result["personal_days_remaining"]
        result["level"] = "critical" if personal <= CRITICAL_DAYS else (
            "warning" if personal <= WARNING_DAYS else "ok")
    except Exception as exc:
        result["level"] = "critical"
        result["error_class"] = type(exc).__name__
    print(json.dumps(result, sort_keys=True))
    return result["level"]

if __name__ == "__main__":
    level = run()
    # Warnings are reported via an issue and then the workflow fails (notifies).
    sys.exit(0 if level == "ok" else 2)
