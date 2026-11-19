"""Offline tests for the separate FI AWG SSH forced-command transport."""
import base64
import importlib.util
from pathlib import Path
import struct
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


stage = module("fi_awg_ssh_stage.py", "fi_awg_ssh_stage")
handler = module("fi_awg_delivery_ssh.py", "fi_awg_delivery_ssh")


class FiAwgForcedSshTests(unittest.TestCase):
    def test_ssh_public_key_must_be_valid_ed25519_with_dedicated_comment(self):
        raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
        encoded = base64.b64encode(raw).decode()
        key = ("ssh-ed25519 " + encoded + " mnebyvpn-fi217-awg-delivery\n").encode()
        self.assertEqual(stage.ssh_public(key)[0], encoded)
        for invalid in (
            key.replace(b"mnebyvpn-fi217-awg-delivery", b"fi-enrollment"),
            key.replace(b"ssh-ed25519", b"ssh-rsa"),
            key.replace(encoded.encode(), b"A"*68),
            key + b"\nssh-ed25519 extra",
            b'command="/bin/bash" ' + key,
            b"ssh-ed25519 AAAA mnebyvpn-fi217-awg-delivery\n",
        ):
            with self.assertRaises(stage.StageBlocked):
                stage.ssh_public(invalid)

    def test_handler_preflight_is_read_only_without_serving_a_shell(self):
        with (mock.patch.object(handler.os, "geteuid", return_value=0),
              mock.patch.object(handler, "check_identity"),
              mock.patch.object(handler, "approved_peer_runtime", return_value=False),
              mock.patch.object(handler.subprocess, "run") as runner):
            self.assertEqual(
                handler.handle(handler.PREFLIGHT),
                "FI_AWG_FORCED_SSH_PREFLIGHT=trusted_channel;AWG_RUNTIME=inactive\n"
            )
            runner.assert_not_called()
        self.assertEqual(stage.PREFLIGHT.encode(), handler.PREFLIGHT)
        self.assertEqual(handler.MAX_COMMAND, 4096)

    def test_rejects_malformed_json_and_unknown_commands_without_exec(self):
        with (mock.patch.object(handler.os, "geteuid", return_value=0),
              mock.patch.object(handler, "check_identity"),
              mock.patch.object(handler.subprocess, "run") as runner):
            for command in (b"false\n", b"{}\n", b'{"nodeId":"x","nodeId":"y"}\n',
                            b"\0\n", b"x"*4097, b"[]\n"):
                with self.assertRaises(handler.DeliveryDenied):
                    handler.handle(command)
            runner.assert_not_called()

    def test_signed_command_does_not_run_without_awg_and_watchdog(self):
        req = {
            "nodeId": "fi-test-01", "op": "revoke",
            "entitlementId": "0e1a2f7b-37ec-4e37-a63d-1df77b40f733",
            "revision": 2, "peerPublicKey": "A"*43+"=",
            "clientIpv4": "10.73.91.254", "expiresAt": None,
            "issuedAt": "2026-11-19T09:00:00.000Z",
            "nonce": "b"*64, "signature": "c"*86,
        }
        fake = types.SimpleNamespace(
            validate_command=mock.Mock(), verify_signature=mock.Mock())
        import json
        data = (json.dumps(req, separators=(",", ":")) + "\n").encode()
        with (mock.patch.object(handler.os, "geteuid", return_value=0),
              mock.patch.object(handler, "check_identity"),
              mock.patch.object(handler, "approved_peer_runtime", return_value=False),
              mock.patch.dict(sys.modules, {"awg_peer_grants": fake}),
              mock.patch.object(handler.subprocess, "run") as runner):
            with self.assertRaisesRegex(handler.DeliveryDenied, "awg_or_watchdog_inactive"):
                handler.handle(data)
            fake.validate_command.assert_called_once()
            fake.verify_signature.assert_called_once()
            runner.assert_not_called()

    def test_forced_command_has_no_shell_or_public_access_path(self):
        assert stage.FORCED.startswith('restrict,command="/usr/bin/python3 ')
        assert stage.FORCED.endswith('fi_awg_delivery_ssh.py"')
        self.assertEqual(stage.NODE_COMMENT, "nodekit-awg-fi217")
        src = (ROOT/"fi_awg_ssh_stage.py").read_text()
        checker = (ROOT/"fi_awg_delivery_ssh.py").read_text()
        for forbidden in ("systemctl start", "systemctl enable", "iptables -A",
                          "docker exec", "INSERT INTO", "UPDATE entitlements",
                          "vpn_release_flags", "peer-grants.json"):
            self.assertNotIn(forbidden, src)
        self.assertNotIn("/bin/sh", stage.FORCED)
        self.assertNotIn("/bin/bash", stage.FORCED)
        self.assertIn('if not approved_peer_runtime():', checker)
        self.assertIn('"--mode", "apply"', checker)
        self.assertIn('if sys.argv[1:]:', checker)
        self.assertIn('PREFIX', "PREFIX")  # explicit sentinel for test structure

    def test_existing_handler_is_readable_on_root_owned_nonprivate_opt_directory(self):
        # On real FI, /opt/mnebyvpn-nodekit is 0755. The handler is owned by
        # root and 0600, but an idempotent rerun must not demand a 0700 parent.
        import os
        import stat
        import tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"fi_awg_delivery_ssh.py"
            path.write_bytes(b"safe-handler")
            mode=stat.S_IFREG|0o600
            rootfile=SimpleNamespace(st_mode=mode,st_uid=0,
                                     st_size=len(b"safe-handler"),st_nlink=1)
            with (mock.patch.object(stage,"HANDLER_PATH",path),
                  mock.patch.object(stage,"trusted_dir") as checked,
                  mock.patch.object(stage.os,"fstat",return_value=rootfile)):
                self.assertEqual(stage.protected(path),b"safe-handler")
                checked.assert_called_once_with(path.parent,private=False)
