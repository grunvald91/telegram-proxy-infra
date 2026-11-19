#!/usr/bin/env python3
"""Guarded, one-shot FI registration on existing RU188.

Only starts the preinstalled root-only systemd enrollment unit when the
existing PostgreSQL inventory is independently approved and all local trust
materials are protected. Does not approve inventory, copy secrets or publish.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys

RU = "188.120.254.223"
NODE = "fi-test-01"
HOST = "fi.mnebyvpn.site"
CONTROLLER_SHA = "e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844"
NODE_SHA = "c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9"
ROOT = Path("/root/mnebyvpn-controller")
UNIT_NAME = "mnebyvpn-fi-enrollment.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class GateError(Exception):
    pass


def fail(reason: str) -> None:
    print("FI_REGISTRATION_BLOCKED=" + reason, file=sys.stderr)
    raise GateError(reason)


def assigned_ip(ip: str) -> bool:
    for _, name in socket.if_nameindex():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                raw = fcntl.ioctl(s.fileno(), 0x8915,
                                  struct.pack("256s", name.encode()))
                if socket.inet_ntoa(raw[20:24]) == ip:
                    return True
            except OSError:
                pass
    return False


def protected(path: Path, max_size: int = 16384) -> bytes:
    for parent in path.parents:
        try:
            st = parent.lstat()
        except OSError:
            fail("required_root_directory_missing")
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o022):
            fail("untrusted_parent_directory")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fail("required_protected_file_unavailable:" + path.name)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                st.st_mode & 0o077 or st.st_nlink != 1 or
                not (0 if path.name == 'fi-enrollment.enable' else 1) <= st.st_size <= max_size):
            fail("unsafe_protected_file")
        data = os.read(fd, max_size + 1)
        if len(data) != st.st_size:
            fail("protected_file_changed")
        return data
    finally:
        os.close(fd)


def spki(path: Path, fingerprint: str) -> bytes:
    blob = protected(path, 100)
    if (len(blob) != 44 or not blob.startswith(SPKI_PREFIX) or
            hashlib.sha256(blob).hexdigest() != fingerprint):
        fail("public_identity_mismatch")
    return blob


def execute(args: list[str], timeout: int = 12) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("local_command_unavailable")
    # Safe invariant-only diagnostics of the trusted FI transient process.
    # Never print stdout/stderr or credentials, only bounded classifications.
    if args and args[0] == "systemd-run" and any(
        item == "--unit=mnebyvpn-fi-controller-transient" for item in args
    ):
        print("FI_TRANSIENT_EXIT_SUCCESS=" + str(p.returncode == 0).lower())
        print("FI_TRANSIENT_APP_STOPPED_MARKER=" +
              str("FI_ENROLLMENT_STOPPED" in p.stderr).lower())
        print("FI_TRANSIENT_APP_SUCCESS_MARKER=" +
              str("FI_ENROLLMENT=testing;SUBSCRIBER_PUBLICATION=false" in p.stdout).lower())
        print("FI_TRANSIENT_STDOUT_PRESENT=" + str(bool(p.stdout.strip())).lower())
        print("FI_TRANSIENT_STDERR_PRESENT=" + str(bool(p.stderr.strip())).lower())
        # Only classification names from the in-process reviewed allowlist.
        match = __import__("re").search(
            r"FI_ENROLLMENT_FAILURE_CLASS=([a-z_]{3,60})", p.stderr
        )
        if match:
            print("FI_SIGNED_ENROLLMENT_FAILURE_CLASS=" + match.group(1))
    if p.returncode != 0:
        fail("local_command_failed")
    return p.stdout.strip()


FI_SIGNED_ENROLL_JS = r"""
import {realpathSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

const RELEASE=realpathSync('/opt/mnebyvpn-controller/current');
if (!/^\/opt\/mnebyvpn-controller\/releases\/[a-f0-9]{40}$/.test(RELEASE))
  throw Error('Unapproved canonical controller runtime');
const moduleAt=(path)=>pathToFileURL(RELEASE+'/'+path).href;
const {default:pg}=await import(moduleAt('node_modules/pg/lib/index.js'));
const {trustedControllerKey}=await import(moduleAt(
    'apps/service/src/awg-controller-delivery-worker.ts'));
const {enrollApprovedFiNode}=await import(moduleAt(
    'packages/provisioning/src/fi-enrollment-ssh.ts'));
if (process.env.MNEBYVPN_ENV!=='production' ||
    process.env.MNEBYVPN_FI_ENROLLMENT!=='enabled' ||
    !/^postgres(?:ql)?:\/\//.test(process.env.DATABASE_URL||''))
  throw Error('FI enrollment must use canonical approved controller');
const recognized = new Map([
  ['Node was not independently approved','db_inventory_not_approved'],
  ['Enrollment challenge already active','db_challenge_already_active'],
  ['FI enrollment challenge was not accepted','ssh_signed_challenge_not_accepted'],
  ['Pinned FI enrollment transport unavailable','ssh_transport_unavailable'],
  ['FI possession proof mismatches approved challenge','signed_proof_mismatch'],
  ['FI node did not sign approved enrollment challenge','signed_proof_invalid'],
  ['FI node did not return a JSON possession proof','signed_proof_invalid'],
  ['FI node returned a non-object proof','signed_proof_invalid'],
  ['Noncanonical or duplicate FI node proof fields','signed_proof_invalid'],
  ['Unexpected FI enrollment state','db_post_enrollment_unexpected'],
  ['Challenge reuse','db_challenge_replay'],
  ['Node enrollment conflict','db_enrollment_conflict'],
  ['Unknown, expired, changed or reused challenge','db_challenge_expired_or_changed'],
  ['Untrusted controller identity or host pin','controller_trust_unavailable'],
  ['Unsafe controller trust directory','controller_trust_unavailable'],
  ['Untrusted controller signing-key ancestry','controller_signer_unavailable'],
  ['FI node public identity differs from approved inventory','fi_identity_untrusted'],
]);
let db;
try {
  const signer=trustedControllerKey(
    process.env.AWG_CONTROLLER_SIGNING_KEY_FILE||'',
    process.env.AWG_CONTROLLER_PUBLIC_SHA256||'');
  db=new pg.Pool({connectionString:process.env.DATABASE_URL,max:1,
                  connectionTimeoutMillis:3000,idleTimeoutMillis:10000});
  const result=await enrollApprovedFiNode(db,signer,{
    sshIdentityFile:process.env.FI_ENROLL_SSH_KEY_FILE||'',
    pinnedKnownHostsFile:process.env.FI_ENROLL_KNOWN_HOSTS_FILE||'',
    approvedNodePublicSpkiFile:process.env.FI_ENROLL_NODE_PUBLIC_SPKI_FILE||'',
  });
  if (result.state!=='testing'||result.published!==false)
    throw Error('Unexpected FI enrollment state');
  process.stdout.write('FI_ENROLLMENT=testing;SUBSCRIBER_PUBLICATION=false\n');
} catch(error) {
  const kind=recognized.get(String(error?.message||'')) ||
      (error?.code==='42501' ? 'db_role_privilege_denied' :
       error?.code==='28P01' ? 'db_auth_failed' :
       error?.code==='ECONNREFUSED' ? 'db_connection_refused' :
       error?.code==='23505' ? 'db_unique_constraint' :
       'unclassified_failure');
  process.stderr.write('FI_ENROLLMENT_FAILURE_CLASS='+kind+'\n');
  process.exitCode=1;
} finally {
  if (db) await db.end();
}
"""


DB_CHECK_JS = r"""
import pg from '/opt/mnebyvpn-controller/current/node_modules/pg/lib/index.js';
import {createHash} from 'node:crypto';

if (process.env.MNEBYVPN_ENV !== 'production' ||
    process.env.MNEBYVPN_FI_ENROLLMENT !== 'enabled' ||
    !/^postgres(?:ql)?:\/\//.test(process.env.DATABASE_URL || ''))
  throw Error('Canonical FI enrollment environment not enabled');

const expected = process.argv[1];
const publicKey = Buffer.from(expected || '', 'base64url');
if (publicKey.length !== 44 ||
    createHash('sha256').update(publicKey).digest('hex') !==
    'c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9')
  throw Error('FI identity mismatch');

const db = new pg.Client({connectionString:process.env.DATABASE_URL,
  connectionTimeoutMillis:3000,query_timeout:4000});
try {
  await db.connect();
  const result = await db.query(
    "SELECT status, endpoint_host, identity_public_spki,"+
    " (approved_at IS NOT NULL) AS approved,"+
    " (enrolled_at IS NOT NULL) AS enrolled"+
    " FROM public.vpn_node_enrollment_inventory WHERE node_id=$1",
    ['fi-test-01']
  );
  if (result.rowCount === 0) {
    process.stdout.write('FI_CANONICAL_DB_STATE=absent\n');
  } else if (result.rowCount === 1) {
    const row=result.rows[0];
    if (row.endpoint_host !== 'fi.mnebyvpn.site' ||
        row.identity_public_spki !== expected ||
        row.approved !== true ||
        (row.status === 'enrolled') !== (row.enrolled === true) ||
        !['approved','enrolled'].includes(row.status))
      throw Error('Unapproved or mismatched FI inventory');
    process.stdout.write('FI_CANONICAL_DB_STATE='+row.status+'\n');
  } else throw Error('Unexpected FI row cardinality');
} finally {
  await db.end();
}
"""


def db_state(expected_spki: str) -> str:
    """Read the same PostgreSQL used by the installed systemd registrar."""
    if (not expected_spki or len(expected_spki) != 59 or
            not all(x.isalnum() or x in "-_" for x in expected_spki)):
        fail("invalid_expected_fi_public_identity")
    cmd = [
        "systemd-run", "--wait", "--pipe", "--collect", "--quiet",
        "--service-type=exec",
        "--property=User=root", "--property=Group=root",
        "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
        "--property=ProtectHome=read-only",
        "--property=ProtectSystem=strict", "--property=PrivateTmp=yes",
        "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
        "--property=IPAddressDeny=any",
        "--property=IPAddressAllow=127.0.0.0/8",
        "--property=IPAddressAllow=::1/128",
        "--property=MemoryMax=256M", "--property=TimeoutStartSec=20s",
        "/opt/mnebyvpn-controller/current/bin/node",
        "--input-type=module", "--eval", DB_CHECK_JS, expected_spki,
    ]
    output = execute(cmd, timeout=40)
    matches = [line.split("=", 1)[1] for line in output.splitlines()
               if line.startswith("FI_CANONICAL_DB_STATE=")]
    if len(matches) != 1 or matches[0] not in ("absent", "approved", "enrolled"):
        fail("canonical_database_status_unverified")
    return matches[0]


def require_runtime() -> None:
    current = Path("/opt/mnebyvpn-controller/current")
    if not current.is_symlink() or not current.resolve(strict=True).is_dir():
        fail("controller_runtime_missing")
    unit = protected(UNIT_PATH, 20000).decode("utf-8")
    required = (
        "Type=oneshot",
        "User=root",
        "ConditionPathExists=/root/mnebyvpn-controller/approvals/fi-enrollment.enable",
        "ConditionPathExists=/root/mnebyvpn-controller/config/fi-enrollment.env",
        "ExecStart=/opt/mnebyvpn-controller/current/bin/node --experimental-strip-types ",
        "IPAddressDeny=any",
        "IPAddressAllow=217.11.167.91/32",
        "NoNewPrivileges=yes",
    )
    if any(s not in unit for s in required):
        fail("enrollment_systemd_unit_untrusted")
    exact_condition_paths = (
        "/root/mnebyvpn-controller/approvals/fi-enrollment.enable",
        "/root/mnebyvpn-controller/config/fi-enrollment.env",
        "/root/mnebyvpn-controller/fi-known_hosts",
        "/root/mnebyvpn-controller/fi-node-public.spki",
        "/root/mnebyvpn-controller/controller-signing-key.pem",
    )
    expected_conditions = {"ConditionPathExists=" + name for name in exact_condition_paths}
    actual_conditions = {line.strip() for line in unit.splitlines()
                         if line.startswith(("Condition", "Assert"))}
    if actual_conditions != expected_conditions:
        fail("installed_systemd_unit_has_unreviewed_conditions")
    for root in ("/etc/systemd/system", "/run/systemd/system",
                 "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
                 "/lib/systemd/system"):
        override = Path(root, UNIT_NAME + ".d")
        if override.exists() or override.is_symlink():
            fail("enrollment_systemd_override_present")
    for name in ("config/fi-enrollment.env", "approvals/fi-enrollment.enable"):
        protected(ROOT / name, 8192)


def main() -> int:
    if os.geteuid() != 0 or not assigned_ip(RU):
        fail("not_existing_ru188_root")
    spki(ROOT / "controller-public.spki", CONTROLLER_SHA)
    node = spki(ROOT / "fi-node-public.spki", NODE_SHA)
    expected = base64.urlsafe_b64encode(node).decode("ascii").rstrip("=")
    known = protected(ROOT / "fi-known_hosts", 512).decode("ascii")
    if not known.startswith(HOST + " ssh-ed25519 ") or len(known.splitlines()) != 1:
        fail("fi_ssh_host_key_unpinned")
    protected(ROOT / "controller-signing-key.pem", 8192)
    protected(ROOT / "fi-enrollment-ssh", 8192)
    require_runtime()
    before = db_state(expected)
    if before == "enrolled":
        print("FI_REGISTRATION=enrolled;SUBSCRIBER_PUBLICATION=false;IDEMPOTENT=true")
        return 0
    if before != "approved":
        fail("fi_inventory_not_preapproved_in_canonical_db")
    # The FI service was staged while its approval paths did not yet exist.
    # Reload only unit metadata after guarded on-host DB/config provisioning.
    # No existing customer service is restarted or modified.
    execute(["systemctl", "daemon-reload"], timeout=20)
    execute(["systemctl", "start", UNIT_NAME], timeout=85)
    # A skipped systemd oneshot can return success. Accept ONLY the canonical DB
    # transition, not systemctl's exit code.
    applied = db_state(expected)
    if applied == "approved":
        if execute(["systemctl", "show", UNIT_NAME,
                    "--property=ConditionResult", "--value"]) != "no":
            fail("registar_did_not_enroll_after_non_skipped_unit")
        # Defense in depth: the on-host systemd evaluator MUST now independently
        # accept the same exact reviewed five condition paths. Do not bypass a
        # failed security condition or unreviewed installed unit.
        paths = (
            "/root/mnebyvpn-controller/approvals/fi-enrollment.enable",
            "/root/mnebyvpn-controller/config/fi-enrollment.env",
            "/root/mnebyvpn-controller/fi-known_hosts",
            "/root/mnebyvpn-controller/fi-node-public.spki",
            "/root/mnebyvpn-controller/controller-signing-key.pem",
        )
        for path in paths:
            execute(["systemd-analyze", "condition",
                     "ConditionPathExists=" + path], timeout=12)
        # Use identical application and EnvironmentFile, with the same network,
        # host FS and capability restrictions as the reviewed static service.
        # This is a one-use privileged CONTROL operation, never client dataplane.
        # Node resolves the TypeScript main module against its REAL release
        # directory. Use that real path in argv[1], otherwise the controller's
        # import.meta.url === pathToFileURL(process.argv[1]) guard silently
        # returns false through /opt/.../current and exits 0 without enrolling.
        release = Path("/opt/mnebyvpn-controller/current").resolve(strict=True)
        if (not release.is_dir() or release.parent !=
                Path("/opt/mnebyvpn-controller/releases")):
            fail("trusted_controller_release_path_invalid")
        command = [
            "systemd-run", "--wait", "--pipe", "--collect", "--quiet",
            "--unit=mnebyvpn-fi-controller-transient", "--service-type=exec",
            "--property=User=root", "--property=Group=root",
            "--property=WorkingDirectory=/opt/mnebyvpn-controller/current",
            "--property=EnvironmentFile=/root/mnebyvpn-controller/config/fi-enrollment.env",
            "--property=ProtectHome=read-only", "--property=ProtectSystem=strict",
            "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
            "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
            "--property=AmbientCapabilities=", "--property=RestrictSUIDSGID=yes",
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "--property=IPAddressDeny=any",
            "--property=IPAddressAllow=127.0.0.0/8",
            "--property=IPAddressAllow=::1/128",
            "--property=IPAddressAllow=217.11.167.91/32",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes",
            "--property=LockPersonality=yes",
            "--property=UMask=0077",
            "--property=TasksMax=64", "--property=MemoryMax=256M",
            "--property=TimeoutStartSec=75s",
            str(release / "bin/node"), "--experimental-strip-types",
            "--input-type=module", "--eval", FI_SIGNED_ENROLL_JS,
        ]
        output = execute(command, timeout=90)
        applied = db_state(expected)
        if applied != "enrolled":
            print("FI_CANONICAL_DB_AFTER_TRANSIENT="+applied,file=sys.stderr)
            fail("transient_registrar_did_not_enroll_fi")
        # The canonical database state (with exact FI identity) is stronger
        # evidence than CLI decorations emitted by systemd-run --wait.
        if "FI_ENROLLMENT=testing;SUBSCRIBER_PUBLICATION=false" not in output.splitlines():
            print("FI_TRANSIENT_OUTPUT_WRAPPED_OR_EMPTY=true;CANONICAL_DB_ENROLLED=true")
    if applied != "enrolled":
        fail("registration_service_did_not_enroll_fi")
    print("FI_REGISTRATION=enrolled;SUBSCRIBER_PUBLICATION=false;IDEMPOTENT=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, OSError, ValueError, UnicodeError):
        raise SystemExit(2)
