import importlib.util
import ipaddress
from pathlib import Path
import struct
import sys
import unittest

module_path = Path(__file__).resolve().parents[1] / "mnebydns_runner_tcp443_return_probe.py"
spec = importlib.util.spec_from_file_location("runner443", module_path)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class ScopedFrameTests(unittest.TestCase):
    target = ipaddress.IPv4Address("203.0.113.55").packed
    local = ipaddress.IPv4Address("192.0.2.123").packed
    dst = {target: "foreign443"}

    def frame(self, incoming=False, flags=2, *, proto=6, target_port=443):
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = proto
        ip[12:16] = self.target if incoming else self.local
        ip[16:20] = self.local if incoming else self.target
        tcp = bytearray(20)
        struct.pack_into("!HH", tcp, 0,
                         target_port if incoming else 50001,
                         50001 if incoming else target_port)
        tcp[13] = flags
        return bytes(ip) + bytes(tcp)

    def test_matching_outgoing_syn(self):
        self.assertEqual(m.packet_event(self.frame(), self.dst), ("foreign443", "SYN", 50001))

    def test_matching_incoming_synack_and_rst(self):
        self.assertEqual(m.packet_event(self.frame(True, 0x12), self.dst), ("foreign443", "SYNACK", 50001))
        self.assertEqual(m.packet_event(self.frame(True, 0x04), self.dst), ("foreign443", "RST", 50001))

    def test_wrong_ip_direction_port_and_protocol_ignored(self):
        self.assertIsNone(m.packet_event(self.frame(proto=17), self.dst))
        self.assertIsNone(m.packet_event(self.frame(target_port=80), self.dst))
        self.assertIsNone(m.packet_event(self.frame(True, 0x10), self.dst))
        self.assertIsNone(m.packet_event(self.frame(), {self.local: "wrong"}))

    def test_truncated_malformed_or_fragmented_ignored(self):
        self.assertIsNone(m.packet_event(b"", self.dst))
        self.assertIsNone(m.packet_event(self.frame()[:20], self.dst))
        pkt = bytearray(self.frame())
        pkt[6:8] = b"\x00\x01"
        self.assertIsNone(m.packet_event(bytes(pkt), self.dst))
        pkt = bytearray(self.frame())
        pkt[0] = 0x60
        self.assertIsNone(m.packet_event(bytes(pkt), self.dst))


if __name__ == "__main__":
    unittest.main()
