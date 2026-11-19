#!/usr/bin/env python3
"""Idempotent RU188 AWG delivery-worker PostgreSQL role + protected env stage.

Automatically stage *only* control-plane trust and least-privilege DB access.
No AWG/watchdog start, no outbox writes, no release approval, no customer
publication, and no worker activation. Generated passwords never leave RU188.
Uses the EXISTING canonical Postgres container, not a new database.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys

RU = "188.120.254.223"
DB_CONTAINER = "mnebyvpn-stage-postgres"
DB = "mnebyvpn_stage"
ROLE = "mnebyvpn_awg_delivery"
PORT = "55433"
ROOT = Path("/root/mnebyvpn-controller")
ENV = ROOT / "config/awg-delivery.env"
PRIVATE = ROOT / "awg-delivery-ssh"
PIN = ROOT / "awg-delivery-known_hosts"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
EXPECTED = (
    "vpn_node_enrollment_inventory",
    "vpn_awg_node_pools",
    "vpn_awg_peer_allocations",
    "vpn_awg_command_outbox",
    "entitlements",
    "vpn_release_flags",
)
# Restrict updates to columns the worker actually uses. Billing and release
# tables remain strictly read-only (no UPDATE/INSERT/DELETE/CREATE/TRUNCATE).
ALLOCATION_UPDATES = (
    "revision", "expires_at", "state", "last_signed_at",
    "last_command_sha256", "applied_at",
)
OUTBOX_UPDATES = (
    "state", "claimed_at", "applied_at", "attempts",
    "node_receipt_sha256",
)


class StageError(ValueError):
    pass


def fail(reason: str) -> None:
    print("FI_AWG_WORKER_DB_STAGE_BLOCKED=" + reason, file=sys.stderr)
    raise StageError(reason)


def assigned(ip: str) -> bool:
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as handle:
            try:
                data = fcntl.ioctl(handle.fileno(), 0x8915,
                                   struct.pack("256s", name.encode()))
                if socket.inet_ntoa(data[20:24]) == ip:
                    return True
            except OSError:
                pass
    return False


def private_dir(path: Path) -> None:
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except OSError:
            fail("missing_root_directories")
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or
                (item in (path, ROOT) and info.st_mode & 0o077)):
            fail("unsafe_root_directory")


def protected(path: Path, max_bytes: int = 8192) -> bytes:
    private_dir(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        fail("missing_protected_asset:" + path.name)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o077 or info.st_nlink != 1 or
                not 1 <= info.st_size <= max_bytes):
            fail("untrusted_protected_asset:" + path.name)
        data = os.read(fd, max_bytes + 1)
        if len(data) != info.st_size:
            fail("protected_asset_changed")
        return data
    finally:
        os.close(fd)


def spki(path: Path, pin: str) -> None:
    data = protected(path, 100)
    if (len(data) != 44 or
            not data.startswith(bytes.fromhex("302a300506032b6570032100")) or
            hashlib.sha256(data).hexdigest() != pin):
        fail("pinned_node_or_controller_mismatch")


def run(args: list[str], input_text: str | None = None, timeout: int = 30) -> str:
    try:
        completed = subprocess.run(args, input=input_text, text=True,
                                   capture_output=True, timeout=timeout,
                                   check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("controller_db_command_unavailable")
    if completed.returncode:
        # Never leak SQL statements, role passwords, psql error text or stderr.
        fail("controller_db_command_failed")
    return completed.stdout.strip()


def sql(query: str) -> str:
    return run(["/usr/bin/docker", "exec", "-i", DB_CONTAINER,
                "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                "-U", DB, "-d", DB], query)


def canonical_db() -> None:
    import json
    raw = run(["/usr/bin/docker", "inspect", DB_CONTAINER])
    state = json.loads(raw)
    if len(state) != 1 or state[0].get("State", {}).get("Running") is not True:
        fail("canonical_postgres_is_not_running")
    bindings = state[0].get("HostConfig", {}).get("PortBindings", {}).get("5432/tcp")
    if (not isinstance(bindings, list) or len(bindings) != 1 or
            bindings[0].get("HostIp") != "127.0.0.1" or
            bindings[0].get("HostPort") != PORT):
        fail("canonical_postgres_port_changed")
    names = ",".join(
        "to_regclass('public." + name + "')::text" for name in EXPECTED)
    result = sql("SELECT current_database()," + names + ";").split("|")
    if len(result) != len(EXPECTED) + 1 or result[0] != DB or any(
            value != name for value, name in zip(result[1:], EXPECTED)):
        fail("required_controller_migrations_not_applied")
    approved = sql(
        "SELECT status,endpoint_host FROM public.vpn_node_enrollment_inventory "
        "WHERE node_id='fi-test-01';")
    if approved != "enrolled|fi.mnebyvpn.site":
        fail("fi_enrollment_not_confirmed")
    # Explicitly preserve closed feature gate: a public-release decision is
    # outside this bootstrap job and MUST NOT be silently enabled.
    if sql(
        "SELECT enabled::text FROM public.vpn_release_flags "
        "WHERE feature='vpn_awg_clients';") != "false":
        fail("awg_client_release_is_not_disabled")
    running = run(["/usr/bin/systemctl", "is-active",
                   "mnebyvpn-awg-delivery.service"], timeout=8)
    if running != "inactive":
        fail("awg_worker_is_not_inactive")


def worker_fields(password: str) -> dict[str, str]:
    return {
        "MNEBYVPN_ENV": "production",
        "MNEBYVPN_AWG_DELIVERY_WORKER": "disabled",
        "DATABASE_URL": (
            "postgresql://" + ROLE + ":" + password +
            "@127.0.0.1:" + PORT + "/" + DB),
        "AWG_CONTROLLER_SIGNING_KEY_FILE": str(ROOT / "controller-signing-key.pem"),
        "AWG_CONTROLLER_PUBLIC_SHA256": CONTROLLER_SHA,
        "AWG_CONTROLLER_SSH_IDENTITY_FILE": str(PRIVATE),
        "AWG_CONTROLLER_SSH_KNOWN_HOSTS_FILE": str(PIN),
    }


def existing_or_new_password() -> tuple[str, bool]:
    if ENV.exists() or ENV.is_symlink():
        data = protected(ENV)
        lines = data.decode("ascii").splitlines()
        fields: dict[str, str] = {}
        for line in lines:
            if line.count("=") < 1:
                fail("unapproved_worker_environment")
            k, v = line.split("=", 1)
            if not re.fullmatch(r"[A-Z0-9_]+", k) or k in fields:
                fail("unapproved_worker_environment")
            fields[k] = v
        match = re.fullmatch(
            r"postgresql://mnebyvpn_awg_delivery:([a-f0-9]{64})"
            r"@127\.0\.0\.1:55433/mnebyvpn_stage",
            fields.get("DATABASE_URL", ""))
        if not match or fields != worker_fields(match.group(1)):
            fail("worker_environment_drift")
        return match.group(1), False
    return secrets.token_hex(32), True


def database_role(password: str, new_env: bool) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", password):
        fail("invalid_generated_password")
    exists = sql("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='" + ROLE +
                 "')::text;")
    if exists not in ("true", "false"):
        fail("unexpected_worker_role_state")
    if exists == "true" and new_env:
        fail("unmanaged_existing_worker_role")
    if exists == "false" and not new_env:
        fail("worker_role_missing_for_existing_config")
    # Prevent unreviewed broad rights accumulated on an existing worker role.
    # Only explicitly enumerated PostgreSQL grants are provisioned.
    create = ("CREATE ROLE " + ROLE + " LOGIN PASSWORD '" + password +
              "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
              "NOBYPASSRLS;") if exists == "false" else ""
    statements = f"""
BEGIN;
{create}
GRANT CONNECT ON DATABASE {DB} TO {ROLE};
GRANT USAGE ON SCHEMA public TO {ROLE};
GRANT SELECT ON public.entitlements,public.vpn_release_flags,
  public.vpn_node_enrollment_inventory,public.vpn_awg_node_pools TO {ROLE};
GRANT SELECT,INSERT ON public.vpn_awg_peer_allocations TO {ROLE};
GRANT UPDATE ({','.join(ALLOCATION_UPDATES)}) ON
  public.vpn_awg_peer_allocations TO {ROLE};
GRANT SELECT,INSERT ON public.vpn_awg_command_outbox TO {ROLE};
GRANT UPDATE ({','.join(OUTBOX_UPDATES)}) ON
  public.vpn_awg_command_outbox TO {ROLE};
GRANT USAGE ON SEQUENCE public.vpn_awg_command_outbox_id_seq TO {ROLE};
COMMIT;"""
    sql(statements)
    # Check the DB role's actual effective rights, not just DDL success.
    checks = sql(f"""
SELECT
  rolsuper::text,rolcreatedb::text,rolcreaterole::text,rolreplication::text,
  rolbypassrls::text
FROM pg_roles WHERE rolname='{ROLE}';""")
    if checks != "false|false|false|false|false":
        fail("worker_role_is_privileged")
    for table in ("entitlements", "vpn_release_flags",
                  "vpn_node_enrollment_inventory", "vpn_awg_node_pools"):
        allowed = sql(
            "SELECT has_table_privilege('" + ROLE + "','public." +
            table + "','SELECT')::text,"
            "has_table_privilege('" + ROLE + "','public." + table +
            "','UPDATE')::text,"
            "has_table_privilege('" + ROLE + "','public." + table +
            "','INSERT')::text,"
            "has_table_privilege('" + ROLE + "','public." + table +
            "','DELETE')::text;")
        if allowed != "true|false|false|false":
            fail("worker_can_modify_billing_release_or_inventory")


def install_env(password: str, is_new: bool) -> None:
    if not is_new:
        protected(ENV)
        return
    blob = "".join(k + "=" + v + "\n" for k, v in worker_fields(password).items())
    # Exclusive creation, no symlinks or secret transmission.
    fd = os.open(ENV, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(ENV.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except Exception:
        ENV.unlink(missing_ok=True)
        raise


def main() -> None:
    if not assigned(RU):
        fail("not_existing_controller188_root")
    private_dir(ROOT)
    private_dir(ENV.parent)
    spki(ROOT / "controller-public.spki", CONTROLLER_SHA)
    spki(ROOT / "fi-node-public.spki", NODE_SHA)
    protected(ROOT / "controller-signing-key.pem")
    protected(PRIVATE)
    known = protected(PIN, 512)
    if known != protected(ROOT / "fi-known_hosts", 512):
        fail("dedicated_fi_host_pin_mismatch")
    # An approved deployment must keep worker activation a separate decision.
    if (ROOT / "approvals/awg-delivery.enable").exists():
        fail("unexpected_existing_awg_worker_approval")
    canonical_db()
    pw, new = existing_or_new_password()
    database_role(pw, new)
    install_env(pw, new)
    print("FI_AWG_WORKER_DB_ROLE=scoped;CANONICAL_DB=verified;"
          "WORKER_ENV=staged_disabled;WORKER_STARTED=false;"
          "CUSTOMER_RELEASE=false;SUBSCRIPTIONS_PUBLISHED=false")


if __name__ == "__main__":
    try:
        main()
    except (StageError, OSError, ValueError, TypeError, KeyError,
            UnicodeError, subprocess.SubprocessError):
        raise SystemExit(2)
