#!/usr/bin/env python3
"""Signed AWG 3.1 peer access contract and reconciliation (non-publishing).

Only an enrolled, pinned Ed25519 controller can authorize a peer. CLI request
files and key material are root-only, never accepted through public HTTP.
The protected JSON table retains revisions even after revocation/expiry.
A future systemd controller-worker must invoke reconcile continuously while
the interface is up; this utility by itself does not promise hard expiry.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from install_components import safe_dir, safe_manifest
from awg_lifecycle import AWG_BIN, INTERFACE, validate as validate_awg

ROOT = Path("/var/lib/mnebyvpn-nodekit")
KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")
KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
NONCE = re.compile(r"[a-f0-9]{64}\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
MAX_LEASE_SECONDS = 7 * 24 * 60 * 60  # Offline availability cap; expires locally, never asks RU188 on handshake
MAX_PEERS = 250
AUTHORIZED_NET = ipaddress.IPv4Network("10.73.91.0/24")
CMD_FIELDS = {
    "nodeId", "op", "entitlementId", "revision", "peerPublicKey",
    "clientIpv4", "expiresAt", "issuedAt", "nonce", "signature",
}
ROW_FIELDS = {"revision", "peerPublicKey", "clientIpv4", "expiresAt", "enabled"}


class GrantError(ValueError):
    pass


def utc_seconds(value: str) -> float:
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise GrantError("Timestamp must be canonical UTC milliseconds")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GrantError("Invalid timestamp") from exc
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        raise GrantError("Noncanonical timestamp")
    return parsed.timestamp()


def valid_uuid(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def valid_key(value: str) -> bool:
    if not isinstance(value, str) or not KEY.fullmatch(value):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode() == value
    except (ValueError, base64.binascii.Error):
        return False


def valid_ipv4(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return (str(address) == value and address in AUTHORIZED_NET and
            2 <= int(str(address).split(".")[-1]) <= 254)


def signed_message(value: dict) -> bytes:
    return json.dumps([
        "MNEBYVPN_AWG_LEASE_V1",
        value["nodeId"], value["op"], value["entitlementId"],
        value["revision"], value["peerPublicKey"], value["clientIpv4"],
        value["expiresAt"], value["issuedAt"], value["nonce"],
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def validate_command(req: dict, node_id: str, now: float) -> None:
    if (not isinstance(req, dict) or set(req) != CMD_FIELDS or
            req["nodeId"] != node_id or req["op"] not in ("grant", "revoke") or
            not valid_uuid(req["entitlementId"]) or
            type(req["revision"]) is not int or
            not 1 <= req["revision"] <= 1_000_000_000 or
            not valid_key(req["peerPublicKey"]) or
            not valid_ipv4(req["clientIpv4"]) or
            not isinstance(req["nonce"], str) or
            not NONCE.fullmatch(req["nonce"]) or
            not isinstance(req["signature"], str) or
            not SIGNATURE.fullmatch(req["signature"])):
        raise GrantError("Invalid AWG peer command")
    if abs(now - utc_seconds(req["issuedAt"])) > 45:
        raise GrantError("Stale controller command")
    if req["op"] == "grant":
        expiry = utc_seconds(req["expiresAt"])
        if not now < expiry <= now + MAX_LEASE_SECONDS:
            raise GrantError("Invalid lease expiration")
    elif req["expiresAt"] is not None:
        raise GrantError("Revocation cannot extend an access lease")


def protected_file(path: Path, *, max_bytes: int = 50000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise GrantError("Protected source is absent or symlinked")
    s = path.stat()
    if (s.st_uid != 0 or s.st_mode & 0o077 or
            not 1 <= s.st_size <= max_bytes):
        raise GrantError("Unsafe protected source ownership or size")
    return path.read_bytes()


def verify_signature(req: dict, public_der: Path,
                     *, runner=subprocess.run) -> None:
    key = protected_file(public_der, max_bytes=100)
    if len(key) != 44 or not key.startswith(KEY_PREFIX):
        raise GrantError("Pinned Ed25519 controller SPKI key required")
    raw_sig = base64.urlsafe_b64decode(req["signature"] + "==")
    if (len(raw_sig) != 64 or
            base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode() !=
            req["signature"]):
        raise GrantError("Invalid Ed25519 signature bytes")
    with tempfile.TemporaryDirectory(prefix="nodekit-awg-verify-") as temp:
        msg = Path(temp) / "command"
        sig = Path(temp) / "signature"
        msg.write_bytes(signed_message(req))
        sig.write_bytes(raw_sig)
        msg.chmod(0o600)
        sig.chmod(0o600)
        try:
            runner([
                "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(public_der), "-keyform", "DER", "-rawin",
                "-in", str(msg), "-sigfile", str(sig),
            ], capture_output=True, check=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            raise GrantError("Untrusted AWG lease signature") from exc


def empty_state(node_id: str) -> dict:
    return {"schema_version": 1, "node_id": node_id, "grants": {}}


def validate_state(raw: dict, node_id: str) -> dict:
    if (not isinstance(raw, dict) or set(raw) !=
            {"schema_version", "node_id", "grants"} or
            raw["schema_version"] != 1 or raw["node_id"] != node_id or
            not isinstance(raw["grants"], dict) or
            len(raw["grants"]) > MAX_PEERS):
        raise GrantError("Invalid AWG grant ledger")
    used_peers, used_ips = set(), set()
    for uid, row in raw["grants"].items():
        if (not valid_uuid(uid) or not isinstance(row, dict) or
                set(row) != ROW_FIELDS or
                type(row["revision"]) is not int or
                not 1 <= row["revision"] <= 1_000_000_000 or
                type(row["enabled"]) is not bool or
                not valid_key(row["peerPublicKey"]) or
                not valid_ipv4(row["clientIpv4"])):
            raise GrantError("Invalid AWG entitlement ledger row")
        if row["enabled"]:
            utc_seconds(row["expiresAt"])
        elif row["expiresAt"] is not None:
            raise GrantError("Disabled peer retains lease expiry")
        # Never allow a previously assigned credential/address to be
        # reassigned to another entitlement without controlled key rotation.
        if row["peerPublicKey"] in used_peers or row["clientIpv4"] in used_ips:
            raise GrantError("Peer credential or client IP collision")
        used_peers.add(row["peerPublicKey"])
        used_ips.add(row["clientIpv4"])
    return raw


def transition(state: dict, req: dict, now: float) -> dict:
    import copy
    validate_command(req, state["node_id"], now)
    updated = copy.deepcopy(validate_state(state, state["node_id"]))
    grants = updated["grants"]
    uid = req["entitlementId"]
    old = grants.get(uid)
    if old is not None:
        if req["revision"] <= old["revision"]:
            raise GrantError("Stale revision or replayed grant")
        if (old["peerPublicKey"] != req["peerPublicKey"] or
                old["clientIpv4"] != req["clientIpv4"]):
            raise GrantError("Implicit key or address rotation forbidden")
    elif req["op"] == "revoke":
        raise GrantError("Unknown entitlement cannot be revoked")
    elif len(grants) >= MAX_PEERS:
        raise GrantError("AWG grant capacity exceeded")
    for existing_id, row in grants.items():
        if existing_id != uid and (
            row["peerPublicKey"] == req["peerPublicKey"] or
            row["clientIpv4"] == req["clientIpv4"]
        ):
            raise GrantError("Duplicate peer public key or client address")
    grants[uid] = {
        "revision": req["revision"],
        "peerPublicKey": req["peerPublicKey"],
        "clientIpv4": req["clientIpv4"],
        "enabled": req["op"] == "grant",
        "expiresAt": req["expiresAt"] if req["op"] == "grant" else None,
    }
    return validate_state(updated, state["node_id"])


def active_peers(state: dict, now: float) -> list[dict]:
    validate_state(state, state["node_id"])
    return sorted([
        {"public_key": row["peerPublicKey"],
         "allowed_ips": row["clientIpv4"] + "/32"}
        for row in state["grants"].values()
        if row["enabled"] and utc_seconds(row["expiresAt"]) > now
    ], key=lambda p: p["allowed_ips"])


def render_runtime_config(base: str, peers: list[dict]) -> str:
    if (not isinstance(base, str) or base.count("[Interface]") != 1 or
            "[Peer]" in base or "PrivateKey = " not in base or
            "HeaderProtectionKey = " not in base):
        raise GrantError("Unexpected baseline AmneziaWG configuration")
    result = [base.rstrip() + "\n"]
    for peer in peers:
        if not valid_key(peer["public_key"]) or not valid_ipv4(
                peer["allowed_ips"].removesuffix("/32")) or not peer["allowed_ips"].endswith("/32"):
            raise GrantError("Invalid peer in runtime view")
        result.append(f"\n[Peer]\nPublicKey = {peer['public_key']}\n"
                      f"AllowedIPs = {peer['allowed_ips']}\n")
    return "".join(result)


def persist_state(path: Path, state: dict) -> None:
    if path.is_symlink():
        raise GrantError("Grant ledger cannot be a symlink")
    if path.exists():
        protected_file(path, max_bytes=50000)
    fd, temp = tempfile.mkstemp(prefix=".grants-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temp).unlink(missing_ok=True)


class OfflineClock:
    """Local authorization clock survives RU188 outages and host time rollback.

    Signed grants never require a network lookup. A monotonic baseline avoids
    extending a paid lease when NTP steps backward during a running session;
    persisted UTC high-watermark catches rollback after reboot.
    """

    def __init__(self, path: Path, *, wall=time.time, monotonic=time.monotonic,
                 load=protected_file, save=persist_state):
        self.path, self.wall, self.monotonic = path, wall, monotonic
        self.save = save
        wall_now = wall()
        if not 0 < wall_now < 4102444800:
            raise GrantError("Unsafe system UTC for offline entitlements")
        last = 0.0
        if path.exists() or path.is_symlink():
            raw = json.loads(load(path, max_bytes=256))
            if (not isinstance(raw, dict) or set(raw) != {"last_seen_ms"} or
                    type(raw["last_seen_ms"]) is not int or
                    not 0 <= raw["last_seen_ms"] < 4102444800000):
                raise GrantError("Unsafe persisted offline clock")
            last = raw["last_seen_ms"] / 1000
        if wall_now + 5 < last:
            raise GrantError("System UTC regressed beyond offline access tolerance")
        self.baseline = max(wall_now, last)
        self.baseline_tick = monotonic()
        self.last_saved = self.baseline
        self._save(self.baseline)

    def _save(self, current: float) -> None:
        self.save(self.path, {"last_seen_ms": int(current * 1000)})
        self.last_saved = current

    def now(self) -> float:
        elapsed = self.monotonic() - self.baseline_tick
        if not 0 <= elapsed < 10 * 365 * 86400:
            raise GrantError("Invalid monotonic clock for offline access")
        projected = self.baseline + elapsed
        wall_now = self.wall()
        if (not 0 < wall_now < 4102444800 or
                wall_now + 5 < max(projected, self.last_saved)):
            raise GrantError("System UTC rollback during offline access")
        current = max(wall_now, projected, self.last_saved)
        if current - self.last_saved >= 15:
            self._save(current)
        return current


def assert_runtime_peers(peers: list[dict], *, runner=subprocess.run) -> None:
    """Validate peer keys AND allowed IPs. A surviving /0 is a breach.

    A key-only comparison would miss externally widened AllowedIPs, thereby
    silently permitting a signed user to impersonate another client address.
    """
    result = runner([str(AWG_BIN / "awg"), "show", INTERFACE, "allowed-ips"],
                    capture_output=True, check=True, text=True, timeout=10)
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        columns = line.split()
        if len(columns) != 2 or columns[0] in observed:
            raise GrantError("Invalid live AWG peer address table")
        observed[columns[0]] = columns[1]
    expected = {row["public_key"]: row["allowed_ips"] for row in peers}
    if observed != expected:
        raise GrantError("Live AWG allowed-ips differ from active entitlements")


def effective_active_peers(node: Path, legacy_state: dict, now: float) -> list[dict]:
    """V1 unchanged unless a root-only V2 ledger AND explicit V2 release exist.

    Both ledgers are read under the SAME LedgerLock as the watchdog/apply.
    A missing or malformed release marker while a V2 ledger exists is fatal:
    it must not silently cause the V1 watcher to discard V2 peers as drift.
    """
    slot_path = node / "amneziawg" / "owner-device-slots-v2.json"
    if not slot_path.exists() and not slot_path.is_symlink():
        return active_peers(legacy_state, now)
    if node.name != "fi-test-01":
        raise GrantError("V2 slot runtime not approved outside FI")
    marker = node / "amneziawg" / "owner-v2-release.json"
    release = json.loads(protected_file(marker, max_bytes=512))
    if (not isinstance(release, dict) or
            set(release) != {"node_id", "enabled"} or
            release["node_id"] != node.name or
            type(release["enabled"]) is not bool or
            release["enabled"] is not True):
        raise GrantError("AWG V2 owner release marker not approved")
    from awg_slot_contract import validate_state as valid_v2, merged_active_peers
    v2_state = valid_v2(json.loads(protected_file(slot_path)), node.name)
    try:
        return merged_active_peers(legacy_state, v2_state, now)
    except ValueError as exc:
        raise GrantError("Incompatible signed V1/V2 peer ledgers") from exc


def reconcile(node: Path, state: dict, now: float, *,
              runner=subprocess.run) -> dict:
    """Synchronize live interface from ledger; on any mismatch STOP AWG."""
    from awg_lifecycle import active_unit, unit_name
    unit = unit_name(node.name)
    try:
        peers = effective_active_peers(node, state, now)
        if not active_unit(unit):
            return {"active": False, "peers": 0, "published": False}
        config = node / "amneziawg" / "awg0.conf"
        if hashlib.sha256(protected_file(config)).hexdigest() != (
                safe_manifest(node / "amneziawg" / "manifest.json")["config_sha256"]):
            raise GrantError("Staged AWG config drift")
        base = runner([str(AWG_BIN / "awg-quick"), "strip", str(config)],
                      capture_output=True, check=True, text=True, timeout=15).stdout
        runtime = render_runtime_config(base, peers)
        fd, filename = tempfile.mkstemp(prefix=".awg-sync-", dir=node / "amneziawg")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(runtime)
            runner([str(AWG_BIN / "awg"), "syncconf", INTERFACE, filename],
                   capture_output=True, check=True, text=True, timeout=15)
        finally:
            Path(filename).unlink(missing_ok=True)
        assert_runtime_peers(peers, runner=runner)
    except BaseException:
        # Invalid/stale peers must never survive an unverified reconciliation.
        runner(["systemctl", "stop", unit], capture_output=True,
               check=False, timeout=40)
        raise
    return {"active": True, "peers": len(peers), "published": False}


def pinned_controller_key(node: Path) -> Path:
    """The same root-only Ed25519 identity approved for Xray supervisor."""
    path = node / "controller-access.spki"
    der = protected_file(path, max_bytes=100)
    if len(der) != 44 or not der.startswith(KEY_PREFIX):
        raise GrantError("Controller public Ed25519 key is not installed")
    return path


def watchdog(node: Path, *, sleeper=time.sleep) -> None:
    """Enforce expirations every 2s; fail closed on corrupt state or failed sync.

    A systemd ExecStopPost additionally tears down awg0 if this Python
    process crashes, is SIGKILL'ed, or its watchdog unit is stopped.
    """
    pinned_controller_key(node)
    from awg_lifecycle import active_unit, unit_name
    unit = unit_name(node.name)
    previous_view: str | None = None
    try:
        clock = OfflineClock(node / "amneziawg" / "clock-highwater.json")
        while True:
            with LedgerLock(node):
                if not active_unit(unit):
                    raise GrantError("AWG interface is no longer managed by systemd")
                path = node / "amneziawg" / "peer-grants.json"
                table = (validate_state(json.loads(protected_file(path)), node.name)
                         if path.exists() or path.is_symlink()
                         else empty_state(node.name))
                now = clock.now()
                peers = effective_active_peers(node, table, now)
                view = json.dumps(peers, sort_keys=True, separators=(",", ":"))
                # Do not run full awg syncconf every 2 seconds on a 1-vCPU VPS.
                # Still verify live peers on every tick to catch drift.
                if view != previous_view:
                    reconcile(node, table, now)
                    previous_view = view
                else:
                    assert_runtime_peers(peers)
            sleeper(2)
    finally:
        subprocess.run(["systemctl", "stop", unit], timeout=35,
                       check=False, capture_output=True)


def signed_node_receipt(node: Path, req: dict, *, runner=subprocess.run) -> dict:
    """Sign a post-reconciliation acknowledgement with NODE identity, not
    the controller. The acknowledged command is fixed by its payload hash.
    """
    priv = node / "identity" / "node-private.pk8"
    pub = node / "identity" / "node-public.spki"
    private_der = protected_file(priv, max_bytes=256)
    public_der = protected_file(pub, max_bytes=100)
    if (not private_der.startswith(bytes.fromhex("302e020100300506032b6570")) or
            len(public_der) != 44 or not public_der.startswith(KEY_PREFIX)):
        raise GrantError("Invalid locally enrolled Ed25519 node identity")
    try:
        derived = runner(
            ["/usr/bin/openssl", "pkey", "-inform", "DER", "-in", str(priv),
             "-pubout", "-outform", "DER"],
            capture_output=True, check=True, timeout=5,
        ).stdout
        if derived != public_der:
            raise GrantError("Node identity private and public keys mismatch")
        receipt = {
            "nodeId": req["nodeId"],
            "op": req["op"],
            "entitlementId": req["entitlementId"],
            "revision": req["revision"],
            "commandSha256": hashlib.sha256(signed_message(req)).hexdigest(),
            "appliedAt": dt.datetime.now(dt.timezone.utc).isoformat(
                timespec="milliseconds").replace("+00:00", "Z"),
            "nonce": secrets.token_hex(32),
        }
        payload = json.dumps([
            "MNEBYVPN_AWG_APPLIED_V1",
            receipt["nodeId"], receipt["op"], receipt["entitlementId"],
            receipt["revision"], receipt["commandSha256"],
            receipt["appliedAt"], receipt["nonce"],
        ], separators=(",", ":")).encode("utf8")
        with tempfile.TemporaryDirectory(prefix="nodekit-awg-ack-") as folder:
            msg = Path(folder) / "payload"
            sig = Path(folder) / "signature"
            msg.write_bytes(payload)
            msg.chmod(0o600)
            runner(
                ["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(priv),
                 "-keyform", "DER", "-rawin", "-in", str(msg), "-out", str(sig)],
                capture_output=True, check=True, timeout=5,
            )
            signature = sig.read_bytes()
        if len(signature) != 64:
            raise GrantError("Unexpected node Ed25519 receipt size")
        return dict(receipt, signature=base64.urlsafe_b64encode(signature)
                    .rstrip(b"=").decode())
    except (OSError, subprocess.SubprocessError) as exc:
        raise GrantError("Could not sign verifiable node receipt") from exc


class LedgerLock:
    """Serialize signed updates, expiry sweeps and reconciliations."""

    def __init__(self, node: Path):
        self.path = node / "amneziawg" / "peer-grants.lock"
        self.fd: int | None = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        st = os.fstat(self.fd)
        if st.st_uid != 0 or st.st_mode & 0o077 or not stat.S_ISREG(st.st_mode):
            os.close(self.fd)
            self.fd = None
            raise GrantError("Unsafe controller ledger lock")
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id", required=True)
    p.add_argument("--mode", choices=("inspect", "verify", "apply", "reconcile", "watchdog", "controller-check"),
                   required=True)
    p.add_argument("--command", type=Path)
    p.add_argument("--stage-root", type=Path, default=ROOT)
    args = p.parse_args()
    try:
        if os.geteuid() != 0:
            raise GrantError("Root required")
        node = args.stage_root / args.node_id
        safe_dir(args.stage_root)
        safe_dir(node)
        safe_dir(node / "amneziawg")
        validate_awg(node)
        if args.mode in ("controller-check", "watchdog"):
            pinned_controller_key(node)
        if args.mode == "watchdog":
            watchdog(node)
            return 0
        if args.mode == "controller-check":
            print(json.dumps({"node_id": node.name, "controller_key_installed": True,
                              "public_subscriptions_enabled": False}, sort_keys=True))
            return 0
        ledger = node / "amneziawg" / "peer-grants.json"
        with LedgerLock(node):
            state = (validate_state(json.loads(protected_file(ledger)), node.name)
                     if ledger.exists() or ledger.is_symlink() else empty_state(node.name))
            now = dt.datetime.now(dt.timezone.utc).timestamp()
            if args.mode in ("verify", "apply"):
                if args.command is None:
                    raise GrantError("Signed command required")
                req = json.loads(protected_file(args.command, max_bytes=4096))
                validate_command(req, node.name, now)
                # Never accept a caller-provided trust anchor. Even an
                # otherwise valid Ed25519 command MUST come from the public
                # key independently pinned during node enrollment.
                verify_signature(req, pinned_controller_key(node))
                planned = transition(state, req, now)
                if args.mode == "apply":
                    # Do NOT grant remote access if AWG is not already running
                    # under an approved service lifecycle.
                    from awg_lifecycle import active_unit, unit_name
                    if (not active_unit(unit_name(node.name)) or
                            not active_unit("mnebyvpn-nodekit-awg-watchdog@" + node.name + ".service")):
                        raise GrantError("AWG and expiry watchdog must both be running")
                    persist_state(ledger, planned)
                    state = planned
            if args.mode in ("reconcile", "apply"):
                from awg_lifecycle import active_unit
                if args.mode == "reconcile" and not active_unit(
                        "mnebyvpn-nodekit-awg-watchdog@" + node.name + ".service"):
                    raise GrantError("No expiry watchdog; refuse standalone reconciliation")
                live = reconcile(node, state, now)
                if args.mode == "apply" and live.get("active") is not True:
                    raise GrantError("AWG interface stopped during access grant")
            else:
                live = {"active": False, "published": False}
            node_receipt = None
            if args.mode == "apply":
                try:
                    node_receipt = signed_node_receipt(node, req)
                except BaseException:
                    # Do not leave a peer active without proof for the
                    # controller's pending command acknowledgement.
                    subprocess.run(
                        ["systemctl", "stop",
                         "mnebyvpn-nodekit-awg@" + node.name + ".service"],
                        capture_output=True, check=False, timeout=35,
                    )
                    raise
            report = {
                "node_id": node.name,
                "signed_command_verified": args.mode in ("verify", "apply"),
                "active_grants": len(active_peers(state, now)),
                "ledger_entries": len(state["grants"]),
                "controller_provisioning_active": False,
                "external_e2e_verified": False,
                **live,
            }
            if node_receipt is not None:
                report["node_receipt"] = node_receipt
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print("nodekit_awg_grants_error=" + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
