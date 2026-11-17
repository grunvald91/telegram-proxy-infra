"""Synthetic fixtures for DE89 TCP/443 and GooglePilot/15449 header parser."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "de89-google-tls-crossleg-readonly-20261117.py"
SPEC = importlib.util.spec_from_file_location("de89_tls_trace", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class HeaderParserTests(unittest.TestCase):
    def test_public_ingress_with_linux_any_prefix(self):
        row = ("1794896052.250182 eth0 In IP 198.51.100.44.41001 > "
               "89.125.90.101.443: Flags [P.], seq 1:1449, ack 1, win 65535, length 1448")
        p = MODULE.parse_packet(row)
        self.assertIsNotNone(p)
        self.assertEqual(MODULE.classify(p), ("PUBLIC_IN",("198.51.100.44",41001)))
        self.assertEqual(p[-1],1448)

    def test_public_reply_small_segment_not_dropped(self):
        row = ("1794896052.490080 eth0 Out IP 89.125.90.101.443 > "
               "198.51.100.44.41001: Flags [P.], seq 1:53, ack 1449, win 65535, length 52")
        p=MODULE.parse_packet(row)
        self.assertEqual(MODULE.classify(p),("PUBLIC_OUT",("198.51.100.44",41001)))
        self.assertEqual(p[-1],52)

    def test_googlepilot_loopback_bidirectional(self):
        one=("1794896052.360000 lo In IP 127.0.0.1.52122 > "
             "127.0.0.1.15449: Flags [P.], length 1448")
        two=("1794896052.390000 lo Out IP 127.0.0.1.15449 > "
             "127.0.0.1.52122: Flags [P.], length 1024")
        self.assertEqual(MODULE.classify(MODULE.parse_packet(one))[0],"PILOT_IN")
        self.assertEqual(MODULE.classify(MODULE.parse_packet(two))[0],"PILOT_OUT")

    def test_older_format_without_interface(self):
        row=("1794896052.250000 IP 198.51.100.44.41001 > "
             "89.125.90.101.443: Flags [S], seq 123, win 65535, length 0")
        p=MODULE.parse_packet(row)
        self.assertEqual(MODULE.classify(p)[0],"PUBLIC_IN")
        self.assertEqual(p[-1],0)

    def test_malformed_and_ipv6_are_not_ipv4(self):
        self.assertIsNone(MODULE.parse_packet("this is not a tcpdump line"))
        self.assertIsNone(MODULE.parse_packet(
            "1794896052.3 eth0 In IP6 ::1.123 > ::1.443: Flags [P.], length 200"))

if __name__=="__main__":
    unittest.main()
