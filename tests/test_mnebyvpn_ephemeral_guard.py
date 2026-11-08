import importlib.util
import os
import pathlib
import sys
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/mnebyvpn-benchmark-ephemeral.py"
spec = importlib.util.spec_from_file_location("ephemeral_test", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class EphemeralGuardTests(unittest.TestCase):
    def test_create_without_explicit_operator_optin_fails_before_key_read(self):
        with patch.object(sys, 'argv', ['ephemeral.py','create','123e4567-e89b-42d3-a456-426614174000']):
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(RuntimeError, 'Refusing disruptive production Xray restart'):
                    mod.main()
    def test_create_optin_reaches_normal_key_validation(self):
        with patch.object(sys, 'argv', ['ephemeral.py','create','123e4567-e89b-42d3-a456-426614174000']):
            with patch.dict(os.environ, {'MNEBYVPN_ALLOW_DISRUPTIVE_LIVE_TEST':'yes'}, clear=True):
                with patch.object(mod,'KEY_PATH',pathlib.Path('/tmp/no-production-secrets-in-test-file')):
                    with self.assertRaises(FileNotFoundError):
                        mod.main()
    def test_revoke_never_blocked_by_create_guard(self):
        with patch.object(sys, 'argv', ['ephemeral.py','revoke','123e4567-e89b-42d3-a456-426614174000']):
            with patch.dict(os.environ, {}, clear=True):
                with patch.object(mod,'KEY_PATH',pathlib.Path('/tmp/no-production-secrets-in-test-file')):
                    with self.assertRaises(FileNotFoundError):
                        mod.main()
if __name__ == '__main__':
    unittest.main()
