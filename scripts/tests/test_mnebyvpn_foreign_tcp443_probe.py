import importlib.util
import ipaddress
from pathlib import Path
import struct
import sys
import unittest

src = Path(__file__).resolve().parents[1] / 'mnebyvpn_foreign_tcp443_probe.py'
spec = importlib.util.spec_from_file_location('tcp443_readonly', src)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class PacketClassificationTest(unittest.TestCase):
    runner = ipaddress.IPv4Address('192.0.2.10').packed
    server = ipaddress.IPv4Address('203.0.113.20').packed

    def frame(self, direction='in', flags=0x02, port=50123, proto=6):
        src, dst = (self.runner, self.server) if direction == 'in' else (self.server, self.runner)
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = proto
        ip[12:16], ip[16:20] = src, dst
        tcp = bytearray(20)
        struct.pack_into('!HH', tcp, 0, port if direction == 'in' else 443,
                         443 if direction == 'in' else port)
        tcp[13] = flags
        return b'\0' * 12 + b'\x08\x00' + bytes(ip) + bytes(tcp)

    def test_tcp_handshake_flags(self):
        self.assertEqual(m.inspect_frame(self.frame('in', 0x02), self.runner, self.server), ('in_syn', 50123))
        self.assertEqual(m.inspect_frame(self.frame('out', 0x12), self.runner, self.server), ('out_synack', 50123))
        self.assertEqual(m.inspect_frame(self.frame('in', 0x10), self.runner, self.server), ('in_ack', 50123))
        self.assertEqual(m.inspect_frame(self.frame('in', 0x04), self.runner, self.server), ('in_rst', 50123))

    def test_non_target_traffic_is_ignored(self):
        self.assertIsNone(m.inspect_frame(self.frame(proto=17), self.runner, self.server))
        self.assertIsNone(m.inspect_frame(self.frame(), self.server, self.runner))
        self.assertIsNone(m.inspect_frame(self.frame()[:30], self.runner, self.server))
        self.assertIsNone(m.inspect_frame(b'\0'*50, self.runner, self.server))

    def test_reject_non_ipv4_and_fragment(self):
        v6 = self.frame()[:12]+b'\x86\xdd'+self.frame()[14:]
        self.assertIsNone(m.inspect_frame(v6,self.runner,self.server))
        pkt=bytearray(self.frame())
        pkt[14+6:14+8] = b'\x00\x01'
        self.assertIsNone(m.inspect_frame(bytes(pkt), self.runner, self.server))


if __name__ == '__main__':
    unittest.main()
