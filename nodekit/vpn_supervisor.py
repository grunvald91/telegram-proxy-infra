#!/usr/bin/env python3
"""Isolated, signed, fail-closed Xray access supervisor for a NEW Nodekit VPS.

Not a network API. Listens only on a root-only UNIX socket inside /run.
Never modifies an existing Xray, nginx, WireGuard, DNS or firewall service.
Must run under an isolated systemd service with KillMode=control-group so a
supervisor crash also terminates its Xray child. NO public node publication.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from vpn_stage import _hash_binary, _private_dir

NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}")
NONCE = re.compile(r"[a-f0-9]{64}")
SIG = re.compile(r"[A-Za-z0-9_-]{86}")
CANONICAL_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z")
PUBLIC_KEY_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_USERS = 2500
MAX_REQUEST = 4096
MAX_DAYS = 100
DEFAULT_ROOT = Path("/var/lib/mnebyvpn-nodekit")
DEFAULT_RUN = Path("/run/mnebyvpn-nodekit")
SERVICE_USER = "mnebyvpn-nodekit-xray"


class AccessError(ValueError):
    pass


def iso_to_time(value: str) -> float:
    if not isinstance(value, str) or not CANONICAL_UTC.fullmatch(value):
        raise AccessError("Timestamp must be canonical UTC milliseconds")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AccessError("Invalid UTC timestamp") from exc
    if parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value:
        raise AccessError("Noncanonical UTC timestamp")
    return parsed.timestamp()


def signed_payload(req: dict) -> bytes:
    return json.dumps([
        "MNEBYVPN_NODEKIT_ACCESS_V1",
        req["nodeId"], req["op"], req["id"], req["revision"],
        req["enabled"], req["expiresAt"], req["issuedAt"], req["nonce"],
    ], separators=(",", ":"), ensure_ascii=False).encode("utf8")


def validate_request(req: object, node_id: str, now: float) -> dict:
    if not isinstance(req, dict) or set(req) != {
        "nodeId", "op", "id", "revision", "enabled", "expiresAt",
        "issuedAt", "nonce", "signature",
    }:
        raise AccessError("Malformed signed access request")
    if req["nodeId"] != node_id or req["op"] not in ("apply", "inspect"):
        raise AccessError("Unknown node or operation")
    try:
        if (not isinstance(req["id"], str) or
                str(uuid.UUID(req["id"])) != req["id"]):
            raise AccessError("Invalid entitlement UUID")
    except (TypeError, ValueError, AttributeError) as exc:
        raise AccessError("Invalid entitlement UUID") from exc
    if not isinstance(req["nonce"], str) or not NONCE.fullmatch(req["nonce"]):
        raise AccessError("Invalid control nonce")
    if not isinstance(req["signature"], str) or not SIG.fullmatch(req["signature"]):
        raise AccessError("Invalid control signature")
    issued = iso_to_time(req["issuedAt"])
    if abs(now - issued) > 45:
        raise AccessError("Expired control request")
    if req["op"] == "inspect":
        if any(req[k] is not None for k in ("revision", "enabled", "expiresAt")):
            raise AccessError("Inspect must not mutate access")
    else:
        if (type(req["revision"]) is not int or
                not 1 <= req["revision"] <= 1_000_000_000 or
                type(req["enabled"]) is not bool):
            raise AccessError("Unsafe access revision or state")
        if req["enabled"]:
            expiry = iso_to_time(req["expiresAt"])
            if not now < expiry <= now + MAX_DAYS * 86400:
                raise AccessError("Invalid hard expiry")
        elif req["expiresAt"] is not None:
            raise AccessError("Revocation must have null expiry")
    return req


def verify_signature(req: dict, public_der: Path, work_dir: Path,
                     openssl: str = "/usr/bin/openssl") -> None:
    """Verify Ed25519 via the host OpenSSL, without extra pip dependencies."""
    try:
        signature = base64.urlsafe_b64decode(req["signature"] + "==")
        if (len(signature) != 64 or
                base64.urlsafe_b64encode(signature).rstrip(b"=").decode() !=
                req["signature"]):
            raise AccessError("Noncanonical Ed25519 signature")
    except (ValueError, base64.binascii.Error) as exc:
        raise AccessError("Unrecognized Ed25519 signature") from exc
    # Only a pinned local controller PUBLIC key is available to this service.
    public = public_der.read_bytes()
    if len(public) != 44 or not public.startswith(PUBLIC_KEY_PREFIX):
        raise AccessError("Invalid controller public key")
    with tempfile.TemporaryDirectory(prefix=".verify-", dir=work_dir) as folder:
        os.chmod(folder, 0o700)
        message = Path(folder) / "message"
        sigfile = Path(folder) / "signature"
        message.write_bytes(signed_payload(req))
        sigfile.write_bytes(signature)
        message.chmod(0o600)
        sigfile.chmod(0o600)
        try:
            subprocess.run([
                openssl, "pkeyutl", "-verify", "-pubin", "-inkey",
                str(public_der), "-keyform", "DER", "-rawin",
                "-in", str(message), "-sigfile", str(sigfile),
            ], capture_output=True, check=True, timeout=3)
        except (OSError, subprocess.SubprocessError) as exc:
            raise AccessError("Invalid controller Ed25519 signature") from exc


def locked_json(path: Path, max_bytes: int) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise AccessError("Invalid root-protected JSON source")
    if path.stat().st_mode & 0o077:
        raise AccessError("Root-protected JSON is readable by others")
    return json.loads(path.read_text(encoding="utf8"))


def atomic_json(path: Path, value: dict) -> None:
    """Root-only crash-durable state. Never resolve symlinks at destination."""
    if path.is_symlink():
        raise AccessError("State file symlink is forbidden")
    fd, temp_name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as stream:
            json.dump(value, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def validate_state(table: object) -> dict:
    if not isinstance(table, dict) or len(table) > MAX_USERS:
        raise AccessError("Invalid state table size")
    for user_id, row in table.items():
        try:
            if str(uuid.UUID(user_id)) != user_id:
                raise ValueError("Invalid UUID")
        except (ValueError, TypeError) as exc:
            raise AccessError("Invalid stored entitlement") from exc
        if (not isinstance(row, dict) or
                set(row) != {"revision", "enabled", "expiresAt", "credential"} or
                type(row["revision"]) is not int or
                not 1 <= row["revision"] <= 1_000_000_000 or
                type(row["enabled"]) is not bool or
                not isinstance(row["credential"], str)):
            raise AccessError("Invalid stored subscriber record")
        try:
            if str(uuid.UUID(row["credential"])) != row["credential"]:
                raise AccessError("Invalid stored credential")
        except ValueError as exc:
            raise AccessError("Invalid stored credential") from exc
        if row["enabled"]:
            iso_to_time(row["expiresAt"])
        elif row["expiresAt"] is not None:
            raise AccessError("Inactive access retains expiry")
    return table


def render_config(template: dict, state: dict, now: float) -> dict:
    config = copy.deepcopy(template)
    clients = [{
        "id": row["credential"],
        "flow": "xtls-rprx-vision",
        "level": 0,
    } for row in state.values() if row["enabled"] and
        iso_to_time(row["expiresAt"]) > now]
    config["inbounds"][0]["settings"]["clients"] = clients
    return config


class NodeAccessSupervisor:
    def __init__(self, node_id: str, stage_root: Path, run_root: Path,
                 xray: Path, controller_pub: Path, child_uid: int, child_gid: int,
                 *, require_root: bool = True, runner=subprocess.run,
                 process_factory=subprocess.Popen, readiness=None,
                 clock=time.time, monotonic=time.monotonic):
        if not isinstance(node_id, str) or not NODE.fullmatch(node_id) or node_id.endswith("-"):
            raise AccessError("Invalid Nodekit ID")
        if require_root and os.geteuid() != 0:
            raise AccessError("Nodekit supervisor requires root")
        _private_dir(stage_root, require_root)
        self.node_dir = stage_root / node_id
        _private_dir(self.node_dir, require_root)
        self.vpn_dir = self.node_dir / "vpn"
        _private_dir(self.vpn_dir, require_root)
        manifest = locked_json(self.node_dir / "manifest.json", 4096)
        stage = locked_json(self.vpn_dir / "vpn-stage-manifest.json", 4096)
        template = locked_json(self.vpn_dir / "xray-config.json", 32768)
        if (manifest.get("node_id") != node_id or
                manifest.get("state") != "testing" or
                manifest.get("activation_enabled") is not False or
                manifest.get("registration_enabled") is not False or
                stage.get("node_id") != node_id or
                stage.get("state") != "staged" or
                stage.get("activation_enabled") is not False or
                stage.get("vpn_users_enabled") is not False or
                stage.get("controller_enrolled") is not False or
                stage.get("independent_e2e_verified") is not False):
            raise AccessError("Supervisor only runs an unpublished Nodekit stage")
        if (_hash_binary(xray, require_root) != stage.get("xray_sha256") or
                manifest.get("listeners", {}).get("vpn_tcp") != stage.get("vpn_port")):
            raise AccessError("Unexpected Xray binary or service port")
        inbounds = template.get("inbounds")
        if (not isinstance(inbounds, list) or len(inbounds) != 1 or
                inbounds[0].get("protocol") != "vless" or
                inbounds[0].get("listen") != "0.0.0.0" or
                inbounds[0].get("port") != stage["vpn_port"] or
                inbounds[0].get("settings", {}).get("clients") != [] or
                inbounds[0].get("streamSettings", {}).get("security") != "reality" or
                inbounds[0].get("streamSettings", {}).get("network") != "tcp" or
                inbounds[0].get("streamSettings", {}).get("realitySettings", {}).get(
                    "shortIds") != [stage["reality_short_id"]] or
                template.get("outbounds") != [{"tag": "direct", "protocol": "freedom"}]):
            raise AccessError("Unexpected staged REALITY configuration")
        if (controller_pub.is_symlink() or not controller_pub.is_file() or
                controller_pub.stat().st_mode & 0o077 or
                (require_root and controller_pub.stat().st_uid != 0)):
            raise AccessError("No protected pinned controller key")
        data = controller_pub.read_bytes()
        if len(data) != 44 or not data.startswith(PUBLIC_KEY_PREFIX):
            raise AccessError("Controller key must be Ed25519 SPKI DER")
        self.node_id = node_id
        self.port = stage["vpn_port"]
        self.template = template
        self.xray = xray
        self.controller_pub = controller_pub
        self.child_uid = child_uid
        self.child_gid = child_gid
        self.runner = runner
        self.process_factory = process_factory
        self.readiness = readiness or self._port_ready
        self.clock = clock
        self.monotonic = monotonic
        self.highwater_path = self.vpn_dir / "clock-highwater.json"
        wall_now = clock()
        if not math.isfinite(wall_now):
            raise AccessError("Invalid clock")
        last_seen = wall_now
        if self.highwater_path.exists() or self.highwater_path.is_symlink():
            clock_record = locked_json(self.highwater_path, 512)
            if (not isinstance(clock_record, dict) or
                    set(clock_record) != {"last_seen_ms"} or
                    type(clock_record["last_seen_ms"]) is not int or
                    clock_record["last_seen_ms"] < 0):
                raise AccessError("Invalid persisted clock high-watermark")
            last_seen = clock_record["last_seen_ms"] / 1000
            if wall_now + 5 < last_seen:
                raise AccessError("System clock regressed: refusing expired access")
        self.baseline = max(wall_now, last_seen)
        self.last_persisted_clock = last_seen
        self.baseline_mono = monotonic()
        self.lock = threading.RLock()
        self.child = None
        self.faulted = False
        self.state_path = self.vpn_dir / "access-state.json"
        self.state = (validate_state(locked_json(self.state_path, 2_000_000))
                      if self.state_path.exists() else {})
        # A monotonic baseline prevents a backward wall-clock adjustment from
        # extending an already started session's UTC entitlement.
        self.run_root = run_root
        if run_root.is_symlink():
            raise AccessError("Runtime parent may not be a symlink")
        run_root.mkdir(parents=True, exist_ok=True, mode=0o755)
        if (run_root.stat().st_mode & 0o022 or
                (require_root and run_root.stat().st_uid != 0)):
            raise AccessError("Runtime root is not a trusted root-owned directory")
        self.runtime = run_root / node_id
        if self.runtime.exists() or self.runtime.is_symlink():
            raise AccessError("Existing runtime directory requires an exclusive service instance")
        self.runtime.mkdir(mode=0o750)
        if require_root:
            os.chown(self.runtime, 0, child_gid)
        self.config_path = self.runtime / "xray-active.json"
        self.socket_path = self.runtime / "control.sock"

    def now(self) -> float:
        return max(self.clock(), self.baseline + self.monotonic() - self.baseline_mono)

    def _port_ready(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                return True
        except OSError:
            return False

    def _render_candidate(self, state: dict) -> Path:
        fd, filename = tempfile.mkstemp(prefix=".candidate-", dir=self.runtime)
        os.close(fd)
        path = Path(filename)
        try:
            config = render_config(self.template, state, self.now())
            path.write_text(json.dumps(config, separators=(",", ":")) + "\n")
            if self.child_gid != os.getgid():
                os.chown(path, 0, self.child_gid)
            path.chmod(0o640)
            validated = self.runner([str(self.xray), "run", "-test", "-config",
                                     str(path)], capture_output=True, timeout=8)
            if validated.returncode != 0:
                raise AccessError("Xray refused a candidate access config")
            return path
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def _stop(self) -> None:
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=2)
        self.child = None

    def _start(self) -> None:
        if self._port_ready():
            raise AccessError("Xray listener already occupied by another process")
        self.child = self.process_factory(
            [str(self.xray), "run", "-config", str(self.config_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, user=self.child_uid, group=self.child_gid,
            extra_groups=(),
        )
        for _ in range(30):
            if self.child.poll() is not None:
                raise AccessError("Dedicated Xray child exited")
            if self.readiness():
                return
            time.sleep(0.1)
        raise AccessError("Dedicated Xray child did not listen")

    def _apply_state(self, candidate: dict, *, critical: bool = False) -> None:
        """For revoke/expiry stop old service FIRST; no stale-user rollback."""
        staged = None
        if not critical:
            # An enable/extension may be validated without disturbing old
            # authorized users. No state or service changes on validation error.
            staged = self._render_candidate(candidate)
        try:
            if critical:
                # Durable revocation BEFORE any risky validation/restart:
                # a crash/reboot may never resurrect revoked/expired users.
                atomic_json(self.state_path, candidate)
                self._stop()
                staged = self._render_candidate(candidate)
            else:
                atomic_json(self.state_path, candidate)
                self._stop()
            os.replace(staged, self.config_path)
            self._start()
            self.state = candidate
        except Exception:
            self.faulted = True
            self._stop()
            raise
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)

    def start(self) -> None:
        with self.lock:
            fresh = copy.deepcopy(self.state)
            for row in fresh.values():
                if row["enabled"] and iso_to_time(row["expiresAt"]) <= self.now():
                    row["enabled"], row["expiresAt"] = False, None
            self._apply_state(fresh)

    def sweep(self) -> None:
        with self.lock:
            if self.faulted:
                raise AccessError("Supervisor is fail-closed")
            current = self.now()
            if current - self.last_persisted_clock >= 15:
                # Persist an anti-rollback watermark even if no access changes.
                atomic_json(self.highwater_path,
                            {"last_seen_ms": int(current * 1000)})
                self.last_persisted_clock = current
            fresh = copy.deepcopy(self.state)
            changed = False
            for row in fresh.values():
                if row["enabled"] and iso_to_time(row["expiresAt"]) <= self.now():
                    row["enabled"], row["expiresAt"] = False, None
                    changed = True
            if changed:
                # Fail closed even if Xray fails to restart with fewer clients.
                self._apply_state(fresh, critical=True)
            elif self.child is None or self.child.poll() is not None:
                self.faulted = True
                self._stop()
                raise AccessError("Dedicated Xray process has stopped")

    def request(self, body: object) -> dict:
        with self.lock:
            if self.faulted:
                raise AccessError("Supervisor not healthy")
            req = validate_request(body, self.node_id, self.now())
            verify_signature(req, self.controller_pub, self.runtime)
            self.sweep()
            row = self.state.get(req["id"])
            if req["op"] == "inspect":
                if not row:
                    return {"revision": 0, "enabled": False, "expiresAt": None}
                active = bool(row["enabled"]) and iso_to_time(row["expiresAt"]) > self.now()
                return {"revision": row["revision"], "enabled": active,
                        "expiresAt": row["expiresAt"] if active else None,
                        "credential": row["credential"] if active else None}
            rev, enabled = req["revision"], req["enabled"]
            if row and rev < row["revision"]:
                return {"status": "stale", "revision": row["revision"]}
            if row and rev == row["revision"]:
                if (row["enabled"] != enabled or
                        (enabled and row["expiresAt"] != req["expiresAt"])):
                    raise AccessError("Same revision conflicts with actual node state")
                return {"status": "applied", "revision": rev}
            if row is None and len(self.state) >= MAX_USERS:
                raise AccessError("Subscriber limit exceeded")
            candidate = copy.deepcopy(self.state)
            candidate[req["id"]] = {
                "revision": rev,
                "enabled": enabled,
                "expiresAt": req["expiresAt"] if enabled else None,
                "credential": row["credential"] if row else str(uuid.uuid4()),
            }
            shrinking_expiry = bool(row and row["enabled"] and enabled and
                                    iso_to_time(req["expiresAt"]) <
                                    iso_to_time(row["expiresAt"]))
            self._apply_state(candidate,
                              critical=(not enabled or shrinking_expiry))
            return {"status": "applied", "revision": rev}

    def shutdown(self) -> None:
        with self.lock:
            self.faulted = True
            self._stop()
            try:
                self.socket_path.unlink(missing_ok=True)
            finally:
                # Runtime config and keys are left only if an unexpected
                # process still holds a file descriptor; no published URI.
                self.config_path.unlink(missing_ok=True)
                try:
                    self.runtime.rmdir()
                except OSError:
                    pass


class LocalControl(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, agent: NodeAccessSupervisor):
        self.agent = agent
        super().__init__(str(agent.socket_path), self.Handler)
        os.chmod(agent.socket_path, 0o600)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(4)
            try:
                raw = self.rfile.readline(MAX_REQUEST + 1)
                if not raw.endswith(b"\n") or len(raw) > MAX_REQUEST:
                    raise AccessError("Unsafe request size")
                body = json.loads(raw)
                result = self.server.agent.request(body)
                payload = {"ok": True, "result": result}
            except (OSError, ValueError, subprocess.SubprocessError):
                payload = {"ok": False, "error": "NODEKIT_PROVISIONING_RETRY_REQUIRED"}
            self.wfile.write(json.dumps(payload, separators=(",", ":")).encode() + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--xray", type=Path, default=Path("/opt/xray/xray"))
    parser.add_argument("--controller-pub", type=Path, required=True)
    parser.add_argument("--stage-root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN)
    args = parser.parse_args()
    if os.geteuid() != 0:
        return 2
    agent = None
    try:
        xray_user = pwd.getpwnam(SERVICE_USER)
        agent = NodeAccessSupervisor(
            args.node_id, args.stage_root, args.run_root, args.xray,
            args.controller_pub, xray_user.pw_uid, xray_user.pw_gid)
        agent.start()
        with LocalControl(agent) as server:
            stop = threading.Event()
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
            signal.signal(signal.SIGINT, lambda *_: stop.set())
            # BaseServer.shutdown() would deadlock without serve_forever().
            server.timeout = 1
            while not agent.faulted and not stop.is_set():
                agent.sweep()
                server.handle_request()
        return 0 if not agent.faulted else 2
    except (OSError, ValueError, subprocess.SubprocessError, KeyError):
        print("nodekit_supervisor_error=FAIL_CLOSED", file=sys.stderr)
        return 2
    finally:
        if agent is not None:
            agent.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
