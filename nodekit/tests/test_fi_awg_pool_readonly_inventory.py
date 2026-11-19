"""FI217 persistent AWG manifest inventory: no peer activation or secrets."""
from pathlib import Path
import importlib.util
import subprocess
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "fi_awg_pool_readonly_inventory.py"
spec = importlib.util.spec_from_file_location("fi_pool_inventory", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FiPoolReadOnlyInventoryTests(unittest.TestCase):
    def test_compiles(self):
        p = subprocess.run(["python3", "-m", "py_compile", str(SCRIPT)],
                           capture_output=True, text=True, timeout=8)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_exact_key_and_digest_formats(self):
        self.assertIsNotNone(module.PUB.fullmatch("A"*43+"="))
        self.assertIsNone(module.PUB.fullmatch("A"*44))
        self.assertIsNone(module.PUB.fullmatch("A"*43+"=bad"))
        self.assertIsNotNone(module.DIGEST.fullmatch("a"*64))
        self.assertIsNone(module.DIGEST.fullmatch("a"*63))

    def test_fail_closed_if_wrong_host(self):
        from unittest.mock import patch
        with patch.object(module, "is_fi", return_value=False):
            with self.assertRaises(module.Blocked):
                module.inspect()

    def test_fail_closed_if_service_status_unknown(self):
        from unittest.mock import patch
        with patch.object(module.subprocess, "run") as execute:
            execute.return_value.returncode = 4
            with self.assertRaises(module.Blocked):
                module.stopped("mnebyvpn-nodekit-awg@fi-test-01.service")

    def test_no_state_mutation_or_private_data_output(self):
        source = SCRIPT.read_text()
        for banned in (
            "systemctl start", "systemctl enable", "systemctl restart",
            "INSERT INTO", "UPDATE public.", "DELETE FROM",
            "awg set", "print(private)", "print(config)",
            "ALTER ROLE", "CREATE ROLE",
        ):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)
        for required in (
            "O_NOFOLLOW", "config_sha256", "source_binary_sha256",
            "server_public_key", "manifest.json", "awg0.conf",
            "subprocess.run(", "PRODUCTION_PROOF=false",
            "CUSTOMER_RELEASE=false",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
