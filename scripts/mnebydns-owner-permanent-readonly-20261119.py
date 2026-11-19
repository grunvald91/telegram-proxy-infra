#!/usr/bin/env python3
"""Read-only diagnosis of owner's permanent personal Smart DNS access.

Never prints owner ID, personal DNS hostname, token/digest, DB credentials,
SQL rows, certificates or application configuration. No writes or restarts.
Public TLS, gateway readiness and permanent authorization are separate tests:
passing TLS alone must NOT be reported as an authenticated owner DNS success.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import secrets
import socket
import ssl
import subprocess
import sys

PUBLIC_IP = "89.125.90.101"
PERSONAL_SUFFIX = ".dns.mnebyvpn.site"
DB_CONTAINER = "mnebyvpn-stage-postgres"
BOT_ENV = pathlib.Path("/opt/mnebyvpn/bot/web.env")
PERSONAL_GATEWAY = "mnebydns-personal-dot-private"
DE_CONFIG = pathlib.Path("/etc/mnebydns/personal-sni/nginx.conf")
DB_SHELL = ('PGPASSWORD="$POSTGRES_PASSWORD" exec psql -XAt '
            '-v ON_ERROR_STOP=1 -h 127.0.0.1 '
            '-U "$POSTGRES_USER" -d "$POSTGRES_DB"')
TIMEOUT = 6


def report(label: str, success: bool) -> bool:
    print("OWNER_DOT_" + label + "=" + ("PASS" if success else "BLOCKED"),
          flush=True)
    return success


def invoke(argv: list[str], *, data: str | None = None, timeout: int = 12):
    return subprocess.run(argv, input=data, capture_output=True, text=True,
                          timeout=timeout, check=False)


def tls(endpoint: str, port: int, hostname: str) -> bool:
    try:
        with socket.create_connection((endpoint, port), timeout=TIMEOUT) as raw:
            raw.settimeout(TIMEOUT)
            with ssl.create_default_context().wrap_socket(
                    raw, server_hostname=hostname) as conn:
                return bool(conn.getpeercert())
    except (OSError, ssl.SSLError, TimeoutError):
        return False


def random_sni() -> str:
    return "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                   for _ in range(12)) + PERSONAL_SUFFIX


def runner() -> bool:
    # A valid public wildcard DoT hostname is a prerequisite to Android
    # Private DNS validation. A public IP-connect bypasses local resolver errors.
    name = random_sni()
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(
                name, 853, type=socket.SOCK_STREAM)
        }
    except OSError:
        addresses = set()
    wildcard = report("PUBLIC_WILDCARD_DNS", PUBLIC_IP in addresses)
    transport = report("PUBLIC_WILDCARD_TLS",
                       tls(PUBLIC_IP, 853, name))
    legacy = report("PUBLIC_LEGACY_TLS",
                    tls(PUBLIC_IP, 853, "dns.mnebyvpn.site"))
    return wildcard and transport and legacy


def service_state(unit: str) -> bool:
    try:
        p = invoke(["systemctl", "is-active", unit], timeout=5)
        return p.returncode == 0 and p.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        return False


def de() -> bool:
    unit = report("DE_PERSONAL_STREAM_ACTIVE",
                  service_state("mnebydns-personal-sni-stream.service"))
    conf = False
    upstream = False
    if DE_CONFIG.is_file() and not DE_CONFIG.is_symlink():
        try:
            text = DE_CONFIG.read_text(encoding="utf-8")
            rules = [line for line in text.splitlines()
                     if "^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" in line]
            conf = len(rules) == 1 and bool(
                re.search(r"\s[^\s;]+:(8856|8858);", rules[0]))
            if conf:
                match = re.search(r"\s([^\s;]+):(8856|8858);", rules[0])
                host, port = match.group(1), int(match.group(2))
                # Scoped private RU upstream only; do not leak IP or route.
                if re.fullmatch(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
                    try:
                        with socket.create_connection(
                                (host, port), timeout=3):
                            upstream = True
                    except OSError:
                        pass
        except (OSError, UnicodeError):
            pass
    route = report("DE_PERSONAL_SNI_ROUTE", conf)
    tunnel = report("DE_TO_RU_PRIVATE_TCP", upstream)
    local_tls = report("DE_PERSONAL_STREAM_TLS",
                       tls("127.0.0.1", 8854, random_sni()))
    return all((unit, route, tunnel, local_tls))


def owner_id() -> str | None:
    try:
        lines = BOT_ENV.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    values = {}
    for line in lines:
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, raw = line.split("=", 1)
        if key in ("DNS_ADMIN_TELEGRAM_ID", "SUPPORT_TELEGRAM_OPERATOR_ID"):
            values[key] = raw.strip().strip("\"'")
    owner = (values.get("DNS_ADMIN_TELEGRAM_ID") or
             values.get("SUPPORT_TELEGRAM_OPERATOR_ID") or "")
    return owner if re.fullmatch(r"[1-9]\d{0,15}", owner) else None


def owner_permanent_inventory() -> dict[str, int] | None:
    owner = owner_id()
    if owner is None:
        return None
    sql = f"""
    SELECT
      COUNT(*) FILTER (WHERE permanent AND video_route='smart_dns'
        AND revoked_at IS NULL AND expires_at IS NULL),
      COUNT(*) FILTER (WHERE permanent AND video_route='vpn_origin'
        AND revoked_at IS NULL AND expires_at IS NULL),
      COUNT(*) FILTER (WHERE permanent AND revoked_at IS NOT NULL),
      COUNT(*) FILTER (WHERE permanent AND expires_at IS NOT NULL),
      COUNT(*) FILTER (WHERE NOT permanent),
      (to_regprocedure('public.owner_dns_link_status(text)') IS NOT NULL)::int
    FROM public.owner_dns_links
    WHERE owner_telegram_id={owner}::bigint;
    """
    try:
        result = invoke(
            ["docker", "exec", "-i", DB_CONTAINER, "sh", "-c", DB_SHELL],
            data=sql, timeout=14)
        if result.returncode != 0:
            return None
        lines = result.stdout.strip().splitlines()
        if len(lines) != 1:
            return None
        fields = lines[0].split("|")
        if len(fields) != 6 or any(
                not re.fullmatch(r"\d{1,6}", x) for x in fields):
            return None
        return dict(zip(("smart", "vpn", "revoked", "not_permanent",
                         "temporary", "status_function"), map(int, fields)))
    except (OSError, subprocess.TimeoutExpired):
        return None


def gateway_env() -> tuple[bool, bool, tuple[str, int] | None]:
    try:
        result = invoke(["docker", "inspect", "--format",
                         "{{json .Config.Env}}", PERSONAL_GATEWAY], timeout=8)
        if result.returncode != 0:
            return False, False, None
        env = dict(item.split("=", 1) for item in json.loads(result.stdout)
                   if isinstance(item, str) and "=" in item)
        enabled = env.get("MNEBYDNS_OWNER_LINKS_ENABLED") == "yes"
        addr = env.get("MNEBYDNS_PERSONAL_DOT_BIND_IP", "")
        port = env.get("MNEBYDNS_PERSONAL_DOT_PORT", "")
        endpoint = None
        if re.fullmatch(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", addr) and (
                port.isdecimal() and 1024 <= int(port) <= 65535):
            endpoint = (addr, int(port))
        state = invoke(["docker", "inspect", "--format",
                        "{{.State.Running}}", PERSONAL_GATEWAY], timeout=8)
        running = state.returncode == 0 and state.stdout.strip() == "true"
        return enabled, running, endpoint
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return False, False, None


def ru() -> bool:
    inventory = owner_permanent_inventory()
    db = report("RU_OWNER_DB_QUERY", inventory is not None)
    smart = report("RU_OWNER_PERMANENT_SMART_DNS",
                   bool(inventory and inventory["smart"] == 1))
    # Legacy route may be present as well, but does not prove SmartDNS.
    if inventory:
        report("RU_OWNER_LEGACY_PERMANENT",
               inventory["vpn"] >= 1)
        report("RU_OWNER_STATUS_FUNCTION",
               inventory["status_function"] == 1)
        report("RU_OWNER_NO_REVOKED_PERMANENT",
               inventory["revoked"] == 0)
    enabled, running, endpoint = gateway_env()
    flag = report("RU_OWNER_GATEWAY_ENABLED", enabled)
    active = report("RU_PERSONAL_GATEWAY_RUNNING", running)
    endpoint_ok = report("RU_PRIVATE_ENDPOINT_DEFINED", endpoint is not None)
    private_tls = report("RU_PRIVATE_PERSONAL_TLS",
                         bool(endpoint and tls(*endpoint, random_sni())))
    return all((db, smart, flag, active, endpoint_ok, private_tls))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("runner", "ru", "de"), required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        assert re.fullmatch(r"[a-z0-9]{12}\.dns\.mnebyvpn\.site",
                            random_sni())
        assert owner_id.__name__ == "owner_id"
        print("OWNER_DOT_DIAGNOSTIC_CONTRACT=PASS")
        return 0
    complete = {"runner": runner, "ru": ru, "de": de}[args.role]()
    print("OWNER_DOT_" + args.role.upper() + "_STATUS=" +
          ("PASS" if complete else "BLOCKED"), flush=True)
    print("OWNER_DOT_AUTHENTICATED_CLIENT_QUERY=NOT_TESTED_NO_BEARER",
          flush=True)
    print("OWNER_DOT_CHANGES=NONE", flush=True)
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
