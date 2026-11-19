#!/usr/bin/env python3
"""Automatically stage RU188's least-privilege AWG delivery DB role (workers OFF).

Existing canonical PostgreSQL, independently pinned RU188/FI217 identities
and the previously installed dedicated AWG SSH channel are prerequisites.
The role can SELECT billing/entitlement and node status, but only write
AWG command outbox and AWG peer-allocation bookkeeping. No subscriber
publication, release flag update, AWG activation or worker start.

Use GitHub Actions to stream this Python module to the existing controller.
Credentials are generated and remain on RU188 in a root-only 0600 env file.
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
ROOT = Path("/root/mnebyvpn-controller")
NODE = "fi-test-01"
HOST = "fi.mnebyvpn.site"
ROLE = "mnebyvpn_awg_delivery"
DB = "mnebyvpn_stage"
DB_CONTAINER = "mnebyvpn-stage-postgres"
PORT = "55433"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
ENV = ROOT / "config/awg-delivery.env"
APPROVAL = ROOT / "approvals/awg-delivery.enable"
UNIT = Path("/etc/systemd/system/mnebyvpn-awg-delivery.service")
PRIVATE = ROOT / "awg-delivery-ssh"
PIN = ROOT / "awg-delivery-known_hosts"
SIGNER = ROOT / "controller-signing-key.pem"
PG_TABLES = ("entitlements", "vpn_node_enrollment_inventory",
             "vpn_awg_node_pools", "vpn_awg_peer_allocations",
             "vpn_awg_command_outbox", "vpn_release_flags")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
CANONICAL_URL_PREFIX = f"postgresql://{ROLE}:"
CANONICAL_URL_SUFFIX = f"@127.0.0.1:{PORT}/{DB}"


class StageError(Exception):
    pass


def stop(label: str) -> None:
    print("FI_AWG_DB_STAGE_BLOCKED=" + label, file=sys.stderr)
    raise StageError(label)


def on_ru() -> bool:
    if os.geteuid() != 0:
        return False
    for _, name in socket.if_nameindex():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                raw = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", name.encode()))
                if socket.inet_ntoa(raw[20:24]) == RU:
                    return True
        except OSError:
            pass
    return False


def trusted_parent(folder: Path) -> None:
    for path in (folder, *folder.parents):
        try:
            item = path.lstat()
        except OSError:
            stop("protected_directory_missing")
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or
                item.st_mode & 0o022 or
                (path == folder and item.st_mode & 0o077)):
            stop("untrusted_protected_directory")


def private_file(path: Path, limit: int = 8192, allow_empty: bool = False) -> bytes:
    trusted_parent(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        stop("private_file_missing")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o077 or info.st_nlink != 1 or
                info.st_size > limit or (info.st_size == 0 and not allow_empty)):
            stop("untrusted_private_file")
        value = os.read(fd, limit + 1)
        if len(value) != info.st_size:
            stop("private_file_changed")
        return value
    finally:
        os.close(fd)


def spki(path: Path, expected: str) -> None:
    actual = private_file(path, 100)
    if (len(actual) != 44 or not actual.startswith(SPKI_PREFIX) or
            hashlib.sha256(actual).hexdigest() != expected):
        stop("pinned_ed25519_identity_mismatch")


def sql(query: str) -> str:
    """Run through container stdin. Never put generated passwords in argv/logs."""
    args = ["docker", "exec", "-i", DB_CONTAINER,
            "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            "-U", DB, "-d", DB]
    try:
        result = subprocess.run(args, input=query, text=True,
                                capture_output=True, check=False, timeout=28)
    except (OSError, subprocess.TimeoutExpired):
        stop("canonical_db_unavailable")
    if result.returncode != 0:
        # stderr can contain SQL, user IDs or credentials: never log it.
        stop("canonical_db_statement_failed")
    return result.stdout.strip()


def bootstrap_env(password: str) -> bytes:
    assert re.fullmatch("[a-f0-9]{64}", password)
    data = {
        "MNEBYVPN_ENV": "production",
        "MNEBYVPN_AWG_DELIVERY_WORKER": "enabled",
        "DATABASE_URL": CANONICAL_URL_PREFIX + password + CANONICAL_URL_SUFFIX,
        "AWG_CONTROLLER_SIGNING_KEY_FILE": str(SIGNER),
        "AWG_CONTROLLER_PUBLIC_SHA256": CONTROLLER_SHA,
        "AWG_CONTROLLER_SSH_IDENTITY_FILE": str(PRIVATE),
        "AWG_CONTROLLER_SSH_KNOWN_HOSTS_FILE": str(PIN),
    }
    return "".join(key + "=" + value + "\n" for key, value in data.items()).encode("ascii")


def environment() -> tuple[str, bool]:
    trusted_parent(ENV.parent)
    if ENV.exists() or ENV.is_symlink():
        actual = private_file(ENV).decode("ascii")
        fields = {}
        for line in actual.splitlines():
            if line.count("=") < 1:
                stop("unapproved_awg_worker_environment")
            key, value = line.split("=", 1)
            if not re.fullmatch("[A-Z0-9_]+", key) or key in fields:
                stop("unapproved_awg_worker_environment")
            fields[key] = value
        match = re.fullmatch(r"postgresql://mnebyvpn_awg_delivery:([a-f0-9]{64})@127\.0\.0\.1:55433/mnebyvpn_stage",
                             fields.get("DATABASE_URL", ""))
        if not match or actual.encode() != bootstrap_env(match.group(1)):
            stop("worker_env_not_canonical")
        return match.group(1), False
    password = secrets.token_hex(32)
    material = bootstrap_env(password)
    fd = os.open(ENV, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(material)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(ENV.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        ENV.unlink(missing_ok=True)
        raise
    return password, True


def role_exists() -> bool:
    state = sql(f"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='{ROLE}')::text;")
    if state not in ("true", "false"):
        stop("unknown_awg_db_role_state")
    return state == "true"


def grant_sql(password: str, new_role: bool) -> str:
    if not re.fullmatch("[a-f0-9]{64}", password):
        stop("unsafe_generated_password")
    create = (f"CREATE ROLE {ROLE} LOGIN NOINHERIT PASSWORD '{password}' "
              "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;"
              if new_role else "")
    # Reader locks are FOR SHARE in Mnebyvpn PR #180. The only FOR UPDATE
    # relations are AWG-controlled outbox and peer allocations. No UPDATE
    # grants are ever given to billing, inventory, release flags or pools.
    return f"""
BEGIN;
{create}
GRANT CONNECT ON DATABASE {DB} TO {ROLE};
GRANT USAGE ON SCHEMA public TO {ROLE};
GRANT SELECT ON public.entitlements,public.vpn_node_enrollment_inventory,
  public.vpn_awg_node_pools,public.vpn_release_flags TO {ROLE};
GRANT SELECT ON public.vpn_awg_peer_allocations,
  public.vpn_awg_command_outbox TO {ROLE};
GRANT INSERT(node_id,entitlement_id,peer_public_key,client_ipv4,
  revision,expires_at,state,last_signed_at,last_command_sha256)
  ON public.vpn_awg_peer_allocations TO {ROLE};
GRANT UPDATE(revision,expires_at,state,last_signed_at,last_command_sha256,applied_at)
  ON public.vpn_awg_peer_allocations TO {ROLE};
GRANT INSERT(node_id,entitlement_id,revision,billing_revision,op,
  signed_command,command_sha256,issued_at,expires_delivery_at)
  ON public.vpn_awg_command_outbox TO {ROLE};
GRANT UPDATE(state,claimed_at,attempts,applied_at,node_receipt_sha256)
  ON public.vpn_awg_command_outbox TO {ROLE};
GRANT USAGE ON SEQUENCE public.vpn_awg_command_outbox_id_seq TO {ROLE};
COMMIT;
"""


def verify_privileges() -> None:
    # Check role attributes + exact relationships. Read-only tables must be
    # inaccessible for INSERT/UPDATE/DELETE even with inherited privileges.
    roles = sql(f"""
SELECT rolcanlogin::text,rolsuper::text,rolinherit::text,
  rolcreatedb::text,rolcreaterole::text,rolreplication::text,rolbypassrls::text,
  (SELECT count(*) FROM pg_auth_members WHERE member=r.oid)::text
FROM pg_roles r WHERE rolname='{ROLE}';
""")
    if roles != "true|false|false|false|false|false|false|0":
        stop("awg_worker_role_has_unapproved_attributes_or_membership")
    for table in ("entitlements", "vpn_node_enrollment_inventory",
                  "vpn_awg_node_pools", "vpn_release_flags"):
        permissions = sql(f"""
SELECT has_table_privilege('{ROLE}','public.{table}','SELECT')::text,
  has_any_column_privilege('{ROLE}','public.{table}','INSERT')::text,
  has_any_column_privilege('{ROLE}','public.{table}','UPDATE')::text,
  has_table_privilege('{ROLE}','public.{table}','DELETE')::text;
""")
        if permissions != "true|false|false|false":
            stop("read_only_billing_or_node_relation_has_write_privilege")
    # Check minimum expected scoped AWG rights, and ensure DELETE is denied.
    for table in ("vpn_awg_peer_allocations", "vpn_awg_command_outbox"):
        permissions = sql(f"""
SELECT has_table_privilege('{ROLE}','public.{table}','SELECT')::text,
  has_any_column_privilege('{ROLE}','public.{table}','INSERT')::text,
  has_any_column_privilege('{ROLE}','public.{table}','UPDATE')::text,
  has_table_privilege('{ROLE}','public.{table}','DELETE')::text;
""")
        if permissions != "true|true|true|false":
            stop("awg_only_relation_privileges_missing_or_too_broad")
    sequence = sql(
        f"SELECT has_sequence_privilege('{ROLE}','public.vpn_awg_command_outbox_id_seq','USAGE')::text;"
    )
    if sequence != "true":
        stop("awg_outbox_identity_sequence_not_authorized")
    # Column-level checks ensure worker cannot rewrite a peer binding.
    denied = (
        ("vpn_awg_peer_allocations", "peer_public_key"),
        ("vpn_awg_peer_allocations", "client_ipv4"),
        ("vpn_awg_peer_allocations", "node_id"),
        ("vpn_awg_peer_allocations", "entitlement_id"),
        ("vpn_awg_command_outbox", "signed_command"),
        ("vpn_awg_command_outbox", "command_sha256"),
        ("vpn_awg_command_outbox", "node_id"),
        ("vpn_awg_command_outbox", "entitlement_id"),
    )
    for table, column in denied:
        check = sql(
            f"SELECT has_column_privilege('{ROLE}','public.{table}',"
            f"'{column}','UPDATE')::text;"
        )
        if check != "false":
            stop("immutable_awg_binding_has_update_permission")


def preflight() -> None:
    if not on_ru():
        stop("not_existing_ru188_root")
    trusted_parent(ROOT)
    spki(ROOT / "controller-public.spki", CONTROLLER_SHA)
    spki(ROOT / "fi-node-public.spki", NODE_SHA)
    private_file(SIGNER)
    private_file(PRIVATE)
    private_file(PIN, 512)
    if private_file(PIN, 512) != private_file(ROOT / "fi-known_hosts", 512):
        stop("awg_ssh_transport_not_independently_pinned")
    if not UNIT.is_file() or UNIT.is_symlink():
        stop("awg_delivery_systemd_unit_not_staged")
    if APPROVAL.exists() or APPROVAL.is_symlink():
        stop("awg_worker_release_marker_must_not_be_enabled")
    try:
        active = subprocess.run(["systemctl", "is-active", "--quiet",
                                 "mnebyvpn-awg-delivery.service"],
                                capture_output=True, timeout=7).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        stop("awg_worker_systemd_state_unknown")
    if active:
        stop("awg_worker_must_remain_off_during_staging")
    state = subprocess.run(["docker", "inspect", DB_CONTAINER, "--format", "{{json .HostConfig.PortBindings}}"],
                           capture_output=True, text=True, timeout=12, check=False)
    if state.returncode:
        stop("canonical_postgres_container_absent")
    import json
    try:
        ports = json.loads(state.stdout)["5432/tcp"]
    except (ValueError, KeyError, TypeError):
        stop("canonical_postgres_port_unverifiable")
    if ports != [{"HostIp": "127.0.0.1", "HostPort": PORT}]:
        stop("canonical_postgres_not_loopback_only")
    answer = sql(
        "SELECT current_database(),"
        + ",".join(f"to_regclass('public.{name}')::text" for name in PG_TABLES)
        + ",to_regclass('public.vpn_awg_command_outbox_id_seq')::text;"
    ).split("|")
    if (len(answer) != len(PG_TABLES) + 2 or answer[0] != DB or
            any(not entry for entry in answer[1:])):
        stop("awg_migrations_not_installed_in_canonical_db")


def inspect() -> None:
    """Read-only scoped role/ACL classification. Never output passwords or rows."""
    preflight()
    if not role_exists():
        print("FI_AWG_DB_INSPECT_ROLE=absent")
        return
    print("FI_AWG_DB_INSPECT_ROLE=present")
    for table in PG_TABLES:
        mask = sql(f"""
SELECT has_table_privilege('{ROLE}','public.{table}','SELECT')::text,
has_table_privilege('{ROLE}','public.{table}','INSERT')::text,
has_any_column_privilege('{ROLE}','public.{table}','INSERT')::text,
has_table_privilege('{ROLE}','public.{table}','UPDATE')::text,
has_any_column_privilege('{ROLE}','public.{table}','UPDATE')::text,
has_table_privilege('{ROLE}','public.{table}','DELETE')::text;
""")
        if len(mask.split("|")) != 6 or any(v not in ("true","false") for v in mask.split("|")):
            stop("unrecognized_scoped_role_permission_matrix")
        print("FI_AWG_DB_INSPECT_"+table.upper()+"="+mask)
    print("FI_AWG_DB_INSPECT_CONFIG_PRESENT="+str(ENV.exists()).lower())
    print("FI_AWG_DB_INSPECT_WORKER=off;SUBSCRIBERS_PUBLISHED=false")


def verify_login(password: str) -> None:
    """Prove scoped role login and SELECT; do NOT grant row-lock permissions."""
    runtime = Path("/opt/mnebyvpn-controller/current/bin/node")
    package = Path("/opt/mnebyvpn-controller/current/node_modules/pg/lib/index.js")
    if not runtime.is_file() or not package.is_file():
        stop("existing_controller_node_pg_runtime_missing")
    js = """
let phase='import',client=null;
try {
  const {default:pg}=await import('/opt/mnebyvpn-controller/current/node_modules/pg/lib/index.js');
  client=new pg.Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3500});
  phase='connect';
  await client.connect();
  phase='identity';
  const result=await client.query('SELECT current_user AS role_name,current_database() AS db_name');
  if(result.rows.length!==1||result.rows[0].role_name!=='mnebyvpn_awg_delivery'||
     result.rows[0].db_name!=='mnebyvpn_stage')
    throw Error('Unexpected authenticated database role');
  phase='read_permissions';
  // PostgreSQL FOR SHARE needs UPDATE privilege on at least one column.
  // Never grant that privilege to this worker on billing or inventory.
  // This stage verifies SELECT only; trusted row locking will require a
  // separately reviewed SECURITY DEFINER gateway before worker activation.
  await client.query('BEGIN');
  for(const table of ['entitlements','vpn_node_enrollment_inventory','vpn_awg_node_pools'])
    await client.query('SELECT * FROM public.'+table+' LIMIT 0');
  await client.query('ROLLBACK');
} catch (e) {
  const code=typeof e?.code==='string'&&/^[0-9A-Z]{5}$/.test(e.code)?e.code:'unclassified';
  process.stderr.write('FI_AWG_DB_LOGIN_CHECK_PHASE='+phase+';PG_CODE='+code+'\\n');
  process.exitCode=2;
} finally {
  if(client)await client.end().catch(()=>{process.exitCode=2;});
}
"""
    env = dict(os.environ)
    env["DATABASE_URL"] = CANONICAL_URL_PREFIX + password + CANONICAL_URL_SUFFIX
    try:
        result = subprocess.run(
            [str(runtime), "--input-type=module", "-e", js],
            capture_output=True, timeout=16, check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        stop("dedicated_awg_db_role_login_unavailable")
    if result.returncode != 0:
        # Never forward stderr verbatim: pg may echo SQL, connection options,
        # or secrets. Only the exact bounded phase + SQLSTATE allowlist.
        for line in result.stderr.decode("ascii",errors="replace").splitlines():
            if re.fullmatch(
                r"FI_AWG_DB_LOGIN_CHECK_PHASE=(import|connect|identity|read_permissions);"
                r"PG_CODE=([0-9A-Z]{5}|unclassified)",line):
                print(line, file=sys.stderr)
        stop("dedicated_awg_db_role_login_or_share_lock_failed")


def main() -> None:
    preflight()
    already = role_exists()
    missing_env = not (ENV.exists() or ENV.is_symlink())
    if already and missing_env:
        # Recovery ONLY for the exact known scoped role with no memberships,
        # no billing/node writes and precisely the expected AWG column ACLs.
        # This repairs the previous partially committed bootstrap, not an
        # arbitrary existing PostgreSQL role. Never escalate this role.
        verify_privileges()
        password, created_env = environment()
        try:
            sql(f"ALTER ROLE {ROLE} PASSWORD '{password}';")
        except BaseException:
            # No release marker exists and worker remains disabled.
            # Future retries may safely perform the same guarded recovery.
            ENV.unlink(missing_ok=True)
            raise
        recovered = True
    else:
        password, created_env = environment()
        # Keep the root-only env on post-commit errors. If PostgreSQL committed
        # before the final check, deleting it leaves an unrecoverable role.
        # If SQL rolled back, a retry creates the role using the same env.
        sql(grant_sql(password, not already))
        recovered = False
    verify_privileges()
    verify_login(password)
    print("FI_AWG_DB_ROLE=scoped;BILLING_WRITES=denied;"
          "NODE_INVENTORY_WRITES=denied;AWG_WORKER=disabled;"
          "ROW_LOCK_GATEWAY_READY=false;SUBSCRIBERS_PUBLISHED=false;RECOVERED=" + str(recovered).lower() +
          ";IDEMPOTENT=" + str(already and not recovered).lower())


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--inspect"]:
            inspect()
        elif sys.argv[1:]:
            stop("unsupported_awg_db_stage_option")
        else:
            main()
    except (StageError, OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.SubprocessError):
        raise SystemExit(2)
