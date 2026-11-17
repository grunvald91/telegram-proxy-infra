"""Offline regression: first install, key pinning, rollback, and empty canary."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

NODEKIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(NODEKIT))
spec = importlib.util.spec_from_file_location("nodekit_install_supervisor",
                                               NODEKIT / "install_supervisor.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RunCommands:
    def __init__(self):
        self.calls = []
        self.fail_start = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["systemctl", "is-active"] and len(self.calls) < 100:
            return subprocess.CompletedProcess(args, 3)
        if args[:2] == ["systemctl", "start"] and self.fail_start:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0)


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        root = Path(self.t.name)
        self.stage = root / "stage"
        self.stage.mkdir(mode=0o700)
        self.node = "de-new-node-01"
        staged = self.stage / self.node
        staged.mkdir(mode=0o700)
        vpn = staged / "vpn"
        vpn.mkdir(mode=0o700)
        self.xray = root / "xray"
        self.xray.write_bytes(b"test-binary-" + b"X" * 20000)
        self.xray.chmod(0o700)
        self.digest = hashlib.sha256(self.xray.read_bytes()).hexdigest()
        self.controller = root / "controller.spki"
        self.controller.write_bytes(m.PUBLIC_KEY_PREFIX + b"\x01" * 32)
        self.controller.chmod(0o600)
        self.pub_digest = hashlib.sha256(self.controller.read_bytes()).hexdigest()
        manifest = {
            "node_id": self.node, "state": "testing", "roles": ["vpn"],
            "activation_enabled": False, "registration_enabled": False,
            "listeners": {"vpn_tcp": 2053},
        }
        stage_manifest = {
            "node_id": self.node, "state": "staged",
            "vpn_users_enabled": False, "activation_enabled": False,
            "controller_enrolled": False, "independent_e2e_verified": False,
            "vpn_port": 2053, "xray_sha256": self.digest,
        }
        config = {"inbounds": [{
            "protocol": "vless", "port": 2053,
            "settings": {"clients": []},
            "streamSettings": {"security": "reality"},
        }]}
        for file, data in [
            (staged / "manifest.json", manifest),
            (vpn / "vpn-stage-manifest.json", stage_manifest),
            (vpn / "xray-config.json", config),
        ]:
            file.write_text(json.dumps(data))
            file.chmod(0o600)
        self.source = root / "sources"
        self.source.mkdir(mode=0o700)
        for file in m.FILES:
            shutil.copyfile(NODEKIT / file, self.source / file)
        shutil.copyfile(
            NODEKIT / "systemd" / m.SOURCE_UNIT, self.source / m.SOURCE_UNIT)
        self.opt = root / "opt"
        self.opt.mkdir()
        self.dest = self.opt / "mnebyvpn-nodekit"
        self.units = root / "etc"
        self.units.mkdir()
        self.unit = self.units / "mnebyvpn-nodekit-vpn@.service"
        self.runner = RunCommands()

    def install(self, *, mode="install", check_canary=None, **kwargs):
        return m.install(
            self.node, self.source, self.controller,
            self.xray, self.digest, self.pub_digest,
            stage_root=self.stage, install_dir=self.dest,
            unit_file=self.unit, mode=mode, require_root=False,
            runner=self.runner,
            service_identity=lambda: (os.getuid() + 4000, os.getgid() + 4000),
            check_canary=check_canary,
            **kwargs)

    def test_install_is_no_start_no_publish_idempotent(self):
        result = self.install()
        self.assertTrue(result["installed"])
        self.assertFalse(result["canary_started"])
        self.assertFalse(result["published"])
        self.assertEqual(self.unit.stat().st_mode & 0o777, 0o644)
        self.assertEqual(
            (self.stage / self.node / "controller-access.spki").stat().st_mode & 0o777,
            0o600)
        self.assertEqual(self.install(), result)
        self.assertFalse(any("start" in cmd for cmd in self.runner.calls))
        for file in m.FILES:
            self.assertEqual((self.dest / file).read_bytes(),
                             (self.source / file).read_bytes())

    def test_tampering_existing_source_or_controller_rejected_no_repair(self):
        self.install()
        original = self.dest / "vpn_supervisor.py"
        original.write_text("tampered existing installation")
        with self.assertRaises(m.InstallError):
            self.install()
        self.assertEqual(original.read_text(), "tampered existing installation")
        original.write_bytes((self.source / "vpn_supervisor.py").read_bytes())
        controller = self.stage / self.node / "controller-access.spki"
        controller.write_bytes(b"not-the-pinned-key")
        with self.assertRaises(m.InstallError):
            self.install()
        self.assertEqual(controller.read_bytes(), b"not-the-pinned-key")

    def test_reject_bad_pub_pin_xray_or_nonempty_state(self):
        self.pub_digest = "b" * 64
        with self.assertRaises(m.InstallError):
            self.install()
        self.pub_digest = hashlib.sha256(self.controller.read_bytes()).hexdigest()
        self.xray.write_bytes(b"tampered" + b"Q" * 20000)
        with self.assertRaises(m.InstallError):
            self.install()
        self.xray.write_bytes(b"test-binary-" + b"X" * 20000)
        state = self.stage / self.node / "vpn" / "access-state.json"
        state.write_text(json.dumps({"unexpected": True}))
        state.chmod(0o600)
        with self.assertRaises(m.InstallError):
            self.install()

    def test_rollback_when_systemd_start_fails_after_partial_launch(self):
        self.runner.fail_start = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.install(mode="canary", check_canary=lambda _: True)
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.stage / self.node / "controller-access.spki").exists())
        self.assertTrue(any(cmd[:2] == ["systemctl", "stop"] for cmd in self.runner.calls))
        self.assertFalse(any(cmd[:2] == ["systemctl", "enable"] for cmd in self.runner.calls))

    def test_canary_only_after_install_and_never_enable(self):
        result = self.install(mode="canary", check_canary=lambda _: True)
        self.assertTrue(result["canary_started"])
        self.assertFalse(result["subscriber_access_enabled"])
        self.assertTrue(any(cmd[:2] == ["systemctl", "start"] for cmd in self.runner.calls))
        self.assertFalse(any(cmd[:2] == ["systemctl", "enable"] for cmd in self.runner.calls))

    def test_canary_socket_check_failure_rolls_back(self):
        with self.assertRaises(m.InstallError):
            self.install(mode="canary", check_canary=lambda _: False)
        self.assertFalse(self.unit.exists())
        self.assertTrue(any(cmd[:2] == ["systemctl", "stop"] for cmd in self.runner.calls))


if __name__ == "__main__":
    unittest.main()
