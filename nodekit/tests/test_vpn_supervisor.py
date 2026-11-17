"""Real OpenSSL Ed25519 signed provisioning + isolated fake-Xray process tests."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import threading
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

NODEKIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(NODEKIT))
import forward_command as nodekit_forward
spec = importlib.util.spec_from_file_location(
    "nodekit_vpn_supervisor", NODEKIT / "vpn_supervisor.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def run(*args):
    subprocess.run(["openssl", *map(str, args)], check=True,
                   capture_output=True, timeout=5)


class FakeChild:
    def __init__(self):
        self.alive = True
        self.killed = False

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.alive = False

    def wait(self, timeout=3):
        return 0

    def kill(self):
        self.alive = False
        self.killed = True


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.fail = False

    def __call__(self, args, **kwargs):
        config = json.loads(Path(args[-1]).read_text())
        self.calls.append(config)
        return subprocess.CompletedProcess(args, 1 if self.fail else 0)


class AccessSupervisorTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        root = Path(self.t.name)
        self.stage_root = root / "stage"
        self.stage_root.mkdir(mode=0o700)
        self.node_id = "nl-test-node-02"
        node = self.stage_root / self.node_id
        node.mkdir(mode=0o700)
        self.vpn = node / "vpn"
        self.vpn.mkdir(mode=0o700)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.xray = root / "xray"
        self.xray.write_bytes(b"fake-pinned-local-binary" + b"\0" * 20000)
        self.xray.chmod(0o700)
        xray_sha = hashlib.sha256(self.xray.read_bytes()).hexdigest()
        manifest = {
            "node_id": self.node_id, "state": "testing",
            "activation_enabled": False, "registration_enabled": False,
            "listeners": {"vpn_tcp": self.port},
        }
        stage = {
            "node_id": self.node_id, "state": "staged",
            "vpn_port": self.port, "xray_sha256": xray_sha,
            "reality_short_id": "abcdef0123456789",
            "activation_enabled": False, "vpn_users_enabled": False,
            "controller_enrolled": False, "independent_e2e_verified": False,
        }
        template = {
            "inbounds": [{
                "protocol": "vless", "listen": "0.0.0.0", "port": self.port,
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "security": "reality", "network": "tcp",
                    "realitySettings": {
                        "shortIds": ["abcdef0123456789"], "privateKey": "TEST-PRIVATE",
                    }
                },
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        }
        for path, item in [
            (node / "manifest.json", manifest),
            (self.vpn / "vpn-stage-manifest.json", stage),
            (self.vpn / "xray-config.json", template),
        ]:
            path.write_text(json.dumps(item))
            path.chmod(0o600)
        self.controller_private = root / "controller-private.pk8"
        self.controller_pub = root / "controller-public.spki"
        run("genpkey", "-algorithm", "ED25519", "-outform", "DER",
            "-out", self.controller_private)
        run("pkey", "-inform", "DER", "-in", self.controller_private,
            "-pubout", "-outform", "DER", "-out", self.controller_pub)
        self.controller_pub.chmod(0o600)
        self.run_root = root / "run"
        self.runner = FakeRunner()
        self.children = []
        self.wall = [time.time()]
        self.mono = [0.0]
        self.agent = None
        self.entitlement = str(uuid.uuid4())

    def new_agent(self):
        def factory(*args, **kwargs):
            self.assertEqual(kwargs["user"], os.getuid())
            self.assertEqual(kwargs["group"], os.getgid())
            child = FakeChild()
            self.children.append(child)
            return child
        agent = m.NodeAccessSupervisor(
            self.node_id, self.stage_root, self.run_root, self.xray,
            self.controller_pub, os.getuid(), os.getgid(),
            require_root=False, runner=self.runner, process_factory=factory,
            readiness=lambda: True, clock=lambda: self.wall[0],
            monotonic=lambda: self.mono[0])
        self.agent = agent
        self.addCleanup(lambda: agent.shutdown())
        return agent

    def signed(self, op="apply", *, revision=1, enabled=True,
               expires_at=None, entitlement=None, **changes):
        now = self.wall[0]
        expiry = expires_at if enabled else None
        if expiry is None and enabled:
            expiry = self.timestamp(now + 65)
        body = {
            "nodeId": self.node_id, "op": op,
            "id": entitlement or self.entitlement,
            "revision": revision if op == "apply" else None,
            "enabled": enabled if op == "apply" else None,
            "expiresAt": expiry if op == "apply" else None,
            "issuedAt": self.timestamp(now), "nonce": "a" * 64,
        }
        body.update(changes)
        with tempfile.TemporaryDirectory() as temp:
            data = Path(temp) / "message"
            sig = Path(temp) / "signature"
            data.write_bytes(m.signed_payload(body))
            run("pkeyutl", "-sign", "-inkey", self.controller_private,
                "-keyform", "DER", "-rawin", "-in", data, "-out", sig)
            body["signature"] = base64.urlsafe_b64encode(
                sig.read_bytes()).rstrip(b"=").decode()
        return body

    @staticmethod
    def timestamp(value):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(value, timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z")

    def test_verified_enable_and_autonomous_expiry_no_controller(self):
        agent = self.new_agent()
        agent.start()
        self.assertEqual(self.runner.calls[-1]["inbounds"][0]["settings"]["clients"], [])
        enabled = self.signed()
        self.assertEqual(agent.request(enabled), {"status": "applied", "revision": 1})
        row = agent.state[self.entitlement]
        credential = row["credential"]
        self.assertEqual(len(agent.state), 1)
        clients = self.runner.calls[-1]["inbounds"][0]["settings"]["clients"]
        self.assertEqual(clients[0]["id"], credential)
        self.assertEqual(clients[0]["flow"], "xtls-rprx-vision")
        self.assertEqual(agent.request(enabled), {"status": "applied", "revision": 1})
        self.mono[0] = 66
        self.wall[0] += 66
        agent.sweep()
        self.assertFalse(agent.state[self.entitlement]["enabled"])
        self.assertIsNone(agent.state[self.entitlement]["expiresAt"])
        self.assertEqual(self.runner.calls[-1]["inbounds"][0]["settings"]["clients"], [])
        self.assertFalse(agent.request(self.signed(op="inspect"))["enabled"])
        with self.assertRaises(m.AccessError):
            agent.request(self.signed(revision=1, enabled=True, expires_at=enabled["expiresAt"]))
        renewed = self.signed(revision=2, enabled=True, expires_at=self.timestamp(self.wall[0]+100))
        self.assertEqual(agent.request(renewed)["status"], "applied")
        self.assertEqual(agent.state[self.entitlement]["credential"], credential)
        self.assertTrue(agent.state[self.entitlement]["enabled"])

    def test_revocation_stops_old_child_even_when_replacement_test_fails(self):
        agent = self.new_agent()
        agent.start()
        agent.request(self.signed())
        self.assertTrue(agent.child.alive)
        self.runner.fail = True
        with self.assertRaises(m.AccessError):
            agent.request(self.signed(revision=2, enabled=False))
        self.assertTrue(agent.faulted)
        self.assertFalse(agent.child or any(p.alive for p in self.children))
        self.assertTrue(self.children[-1].killed or self.children[-2].killed)
        persisted = json.loads(agent.state_path.read_text())
        self.assertFalse(persisted[self.entitlement]["enabled"])
        self.assertIsNone(persisted[self.entitlement]["expiresAt"])

    def test_invalid_signature_never_mutates_xray_or_state(self):
        agent = self.new_agent()
        agent.start()
        req = self.signed()
        before = len(self.runner.calls)
        for mutation in [
            {**req, "nodeId": "nl-fake-node-02"},
            {**req, "id": str(uuid.uuid4())},
            {**req, "revision": 2},
            {**req, "enabled": False},
            {**req, "nonce": "b" * 64},
            {**req, "signature": "A" * 86},
            {**req, "issuedAt": self.timestamp(self.wall[0]-100)},
            {**req, "expiresAt": self.timestamp(self.wall[0]+101*86400)},
        ]:
            with self.subTest(mutation=mutation), self.assertRaises(m.AccessError):
                agent.request(mutation)
        self.assertEqual(len(self.runner.calls), before)
        self.assertFalse(agent.state)
        self.assertFalse(agent.faulted)

    def test_no_enable_if_xray_config_fails_preflight(self):
        agent = self.new_agent()
        agent.start()
        self.runner.fail = True
        child = agent.child
        with self.assertRaises(m.AccessError):
            agent.request(self.signed())
        self.assertTrue(child.alive)
        self.assertFalse(agent.faulted)
        self.assertEqual(agent.state, {})

    def test_signed_revocation_new_user_and_stale_revision(self):
        agent = self.new_agent()
        agent.start()
        self.assertEqual(agent.request(self.signed(revision=2, enabled=False))["status"], "applied")
        self.assertFalse(agent.state[self.entitlement]["enabled"])
        self.assertEqual(agent.request(self.signed(revision=1, enabled=True))["status"], "stale")
        self.assertEqual(agent.request(self.signed(revision=2, enabled=False))["status"], "applied")
        with self.assertRaises(m.AccessError):
            agent.request(self.signed(revision=2, enabled=True))
        self.assertFalse(agent.state[self.entitlement]["enabled"])

    def test_persisted_clock_prevents_backward_boottime_resurrection(self):
        agent = self.new_agent()
        agent.start()
        agent.request(self.signed())
        self.wall[0] += 20
        self.mono[0] += 20
        agent.sweep()
        agent.shutdown()
        self.wall[0] -= 30
        with self.assertRaises(m.AccessError):
            self.new_agent()
        self.wall[0] += 40
        recovered = self.new_agent()
        recovered.start()
        self.assertTrue(recovered.state[self.entitlement]["enabled"])

    def test_root_only_unix_control_roundtrip_and_failed_signature(self):
        agent = self.new_agent()
        agent.start()
        with m.LocalControl(agent) as server:
            self.assertEqual(agent.socket_path.stat().st_mode & 0o777, 0o600)
            server.timeout = 2
            def ask(body):
                accept = threading.Thread(target=server.handle_request, daemon=True)
                accept.start()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(3)
                    connection.connect(str(agent.socket_path))
                    connection.sendall(json.dumps(body).encode() + b"\n")
                    raw = bytearray()
                    while not raw.endswith(b"\n"):
                        raw.extend(connection.recv(4096))
                accept.join(timeout=2)
                return json.loads(raw)
            valid = self.signed()
            good = ask(valid)
            self.assertTrue(good["ok"])
            self.assertEqual(good["result"]["revision"], 1)
            bad = ask({**valid, "enabled": False})
            self.assertFalse(bad["ok"])
            self.assertEqual(
                bad["error"], "NODEKIT_PROVISIONING_RETRY_REQUIRED")
            inspected = ask(self.signed(op="inspect"))
            self.assertTrue(inspected["ok"])
            self.assertTrue(inspected["result"]["enabled"])
            self.assertEqual(inspected["result"]["credential"],
                             agent.state[self.entitlement]["credential"])

    def test_real_ed25519_ssh_bridge_to_local_supervisor_expiry_and_revoke(self):
        # Only the SSH hop is simulated; everything after its root-only
        # command uses actual OpenSSL Ed25519 and UNIX socket transport.
        agent = self.new_agent()
        agent.start()
        with m.LocalControl(agent) as server:
            server.timeout = 2

            def send(command):
                listener = threading.Thread(target=server.handle_request,
                                            daemon=True)
                listener.start()
                payload = json.dumps(command).encode() + b"\n"
                response = nodekit_forward.deliver(
                    self.node_id, payload, run_root=self.run_root,
                    require_root=False)
                listener.join(timeout=3)
                return json.loads(response)["result"]

            issued = send(self.signed(revision=1, enabled=True))
            self.assertEqual(issued["status"], "applied")
            inspected = send(self.signed(op="inspect"))
            self.assertTrue(inspected["enabled"])
            self.assertEqual(inspected["credential"],
                             agent.state[self.entitlement]["credential"])
            old_child = agent.child
            revoked = send(self.signed(revision=2, enabled=False))
            self.assertEqual(revoked["revision"], 2)
            self.assertTrue(old_child.killed)
            self.assertFalse(agent.state[self.entitlement]["enabled"])
            stale = send(self.signed(revision=1, enabled=True))
            self.assertEqual(stale["status"], "stale")
            self.assertFalse(agent.state[self.entitlement]["enabled"])
            send(self.signed(revision=3, enabled=True))
            self.wall[0] += 70
            self.mono[0] += 70
            agent.sweep()
            self.assertFalse(agent.state[self.entitlement]["enabled"])

    def test_stored_duplicate_credential_fails_closed_on_startup(self):
        entry = {"revision": 1, "enabled": False,
                 "expiresAt": None, "credential": str(uuid.uuid4())}
        other = str(uuid.uuid4())
        (self.vpn / "access-state.json").write_text(json.dumps({
            self.entitlement: entry, other: dict(entry),
        }))
        (self.vpn / "access-state.json").chmod(0o600)
        with self.assertRaises(m.AccessError):
            self.new_agent()

    def test_nonroot_xray_must_be_able_to_execute_pinned_binary(self):
        fake_uid, fake_gid = os.getuid() + 4000, os.getgid() + 4000
        self.assertFalse(m.child_can_execute(self.xray, fake_uid, fake_gid))
        self.xray.chmod(0o755)
        Path(self.t.name).chmod(0o755)
        self.assertTrue(m.child_can_execute(self.xray, fake_uid, fake_gid))
        self.xray.chmod(0o700)
        self.assertFalse(m.child_can_execute(self.xray, fake_uid, fake_gid))

    def test_unpublished_stage_and_exact_xray_binary_required(self):
        self.xray.write_bytes(b"tampered" + b"0" * 20000)
        with self.assertRaises(m.AccessError):
            self.new_agent()
        self.xray.write_bytes(b"fake-pinned-local-binary" + b"\0" * 20000)
        config = self.vpn / "xray-config.json"
        template = json.loads(config.read_text())
        template["inbounds"][0]["settings"]["clients"] = [{"id": "nonempty"}]
        config.write_text(json.dumps(template))
        with self.assertRaises(m.AccessError):
            self.new_agent()


if __name__ == "__main__":
    unittest.main()
