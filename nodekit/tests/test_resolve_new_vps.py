import importlib.util
from pathlib import Path
import socket
import unittest

PATH = Path(__file__).resolve().parents[1] / "resolve_new_vps.py"
loader = importlib.util.spec_from_file_location("nodekit_resolve", PATH)
module = importlib.util.module_from_spec(loader)
loader.loader.exec_module(module)


def fake(*ips):
    def resolver(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 22))
                for ip in ips]
    return resolver


class VpsTargetSafety(unittest.TestCase):
    def test_pins_one_global_host(self):
        self.assertEqual(module.safe_target_ip("new-node.example.net",
                         resolver=fake("8.8.4.4", "1.1.1.1")),
                         "1.1.1.1")

    def test_blocks_aliases_for_live_nodes(self):
        for ips in [
            ("89.125.90.101",),
            ("188.120.254.223",),
            ("1.1.1.1", "89.125.90.101"),
            ("127.0.0.1",),
            ("10.0.0.1",),
            ("169.254.1.1",),
            ("203.0.113.50",),
            ("0.0.0.0",),
        ]:
            with self.subTest(ips=ips), self.assertRaises(module.TargetError):
                module.safe_target_ip("new-node.example.net", resolver=fake(*ips))

    def test_malformed_host_or_absent_dns(self):
        for host in ["../x", "node..example.net", "node.-invalid.net", 
                     "evil name", "nodé.example.net", "-node.example.net"]:
            with self.subTest(host=host), self.assertRaises(module.TargetError):
                module.safe_target_ip(host, resolver=fake("8.8.4.4"))
        with self.assertRaises(module.TargetError):
            module.safe_target_ip("new-node.example.net", resolver=fake())


if __name__ == "__main__":
    unittest.main()
