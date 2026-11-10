#!/usr/bin/env python3
"""Offline tests: no VPS access and no privileged packet injection."""
import importlib.util
import ipaddress
import struct
from pathlib import Path
from unittest import TestCase, main

FILE = Path(__file__).resolve().parents[1] / "mnebydns_synack_window_canary.py"
spec = importlib.util.spec_from_file_location("mnebydns_window", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SERVER = "188.120.254.223"
CLIENT = "203.0.113.27"  # reserved test address; must never be used in production
OTHER = "203.0.113.28"


def sample(flags=0x12, *, options=b"\x03\x03\x07\x01", src=SERVER, dst=CLIENT,
           sport=443, window=64240, payload=b"", frag=0):
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
        self.assertEqual(struct.unpack_from("!H", after, 20 + 14)[0], 4)
        self.assertEqual(after[:20], before[:20])
        self.assertEqual(after[20:34], before[20:34])
        self.assertEqual(after[38:], before[38:])  # options preserved, especially WS=7
        pseudo = before[12:20] + struct.pack("!BBH", 0, 6, len(after) - 20)
        self.assertEqual(m.checksum(pseudo + after[20:]), 0)

    def test_ignores_other_packets(self):
        tests = [sample(flags=0x10), sample(flags=0x02), sample(dst=OTHER),
                 sample(src=OTHER), sample(sport=8443), sample(payload=b"hello"),
                 sample(frag=0x2000), sample(frag=1), b"not-an-ipv4-packet",
                 sample()[:-4], sample(flags=0x18), sample(flags=0x52)]
        for packet in tests:
            with self.subTest(packet=repr(packet[:12])):
                self.assertEqual(self.change(packet), packet)

    def test_rejects_bad_parameters(self):
        for window in (0, 65536):
            with self.assertRaises(ValueError):
                m.clamp_synack(sample(), server=SERVER, client=CLIENT, window=window)


if __name__ == "__main__":
    main()
