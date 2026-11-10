#!/usr/bin/env python3
"""Transport-byte tests; no privileged packet injection or VPS access."""
import importlib.util
import ipaddress
import struct
import sys
from pathlib import Path
from unittest import TestCase, main

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
spec = importlib.util.spec_from_file_location("mnebydns_window", BASE / "mnebydns_synack_window_canary.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SERVER = "188.120.254.223"
CLIENT = "203.0.113.27"
OTHER = "203.0.113.28"


def sample(flags=0x12, *, options=b"\x03\x03\x07\x01", src=SERVER,
           dst=CLIENT, sport=18443, window=64240, payload=b"", frag=0):
    tcp_len = 20 + len(options) + len(payload)
    ip_len = 20 + tcp_len
    ip = bytearray(20)
    struct.pack_into("!BBHHHBBH", ip, 0, 0x45, 0, ip_len, 1, frag, 64, 6, 0)
    ip[12:16] = ipaddress.IPv4Address(src).packed
    ip[16:20] = ipaddress.IPv4Address(dst).packed
    struct.pack_into("!H", ip, 10, m.checksum(ip))
    tcp = bytearray(20 + len(options))
    struct.pack_into("!HHII", tcp, 0, sport, 55432, 100, 200)
    tcp[12] = ((20 + len(options)) // 4) << 4
    tcp[13] = flags
    struct.pack_into("!H", tcp, 14, window)
    tcp[20:] = options
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, tcp_len)
    struct.pack_into("!H", tcp, 16, m.checksum(pseudo + tcp + payload))
    return bytes(ip + tcp + payload)


class WindowCanaryTests(TestCase):
    def change(self, packet):
        return m.clamp_synack(packet, server=SERVER, client=CLIENT)

    def test_exact_synack_clamps_only_window_and_tcp_checksum(self):
        before = sample()
        after = self.change(before)
        self.assertNotEqual(before, after)
        self.assertEqual(struct.unpack_from("!H", after, 34)[0], 4)
        self.assertEqual(after[:20], before[:20])
        self.assertEqual(after[20:34], before[20:34])
        self.assertEqual(after[38:], before[38:])
        pseudo = before[12:20] + struct.pack("!BBH", 0, 6, len(after) - 20)
        self.assertEqual(m.checksum(pseudo + after[20:]), 0)

    def test_ecn_synack_keeps_ecn_flag_and_options(self):
        before = sample(flags=0xd2)  # SYN|ACK|ECE|CWR
        after = self.change(before)
        self.assertNotEqual(before, after)
        self.assertEqual(before[33], after[33])
        self.assertEqual(before[40:], after[40:])

    def test_ignores_every_unrelated_packet(self):
        cases = [sample(flags=0x10), sample(flags=0x02), sample(dst=OTHER),
                 sample(src=OTHER), sample(sport=443), sample(sport=18444),
                 sample(payload=b"hello"), sample(frag=0x2000), sample(frag=1),
                 b"not-ip", sample()[:-4], sample(flags=0x18),
                 sample(flags=0x1a)]
        for packet in cases:
            with self.subTest(packet=repr(packet[:15])):
                self.assertEqual(self.change(packet), packet)

    def test_rejects_production_port_and_bad_windows(self):
        for port in (443, 8443, 0, 18444):
            with self.assertRaises(ValueError):
                m.clamp_synack(sample(), server=SERVER, client=CLIENT, port=port)
        for window in (0, 65536):
            with self.assertRaises(ValueError):
                m.clamp_synack(sample(), server=SERVER, client=CLIENT, window=window)


if __name__ == "__main__":
    main()
