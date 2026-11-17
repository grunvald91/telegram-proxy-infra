import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import dot_local_canary as m


class TestDoTCanary(unittest.TestCase):
    def test_make_valid_dns_query(self):
        req = m.dns_wire("fi.mnebyvpn.site", 0x1234)
        self.assertEqual(req[:2], b"\x12\x34")
        self.assertEqual(req[12:15], b"\x02fi")
        self.assertTrue(req.endswith(b"\x00\x00\x01\x00\x01"))

    def test_real_a_response_parsing(self):
        req = m.dns_wire("fi.mnebyvpn.site", 0x2345)
        question = req[12:]
        header = struct.pack(">HHHHHH", 0x2345, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4)
        answer += bytes([217, 11, 167, 91])
        self.assertEqual(m.parse_a(header + question + answer, 0x2345),
                         ["217.11.167.91"])

    def test_rejects_wrong_dns_id_and_failure_status(self):
        req = m.dns_wire("fi.mnebyvpn.site", 0x1234)
        packet = struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0) + req[12:]
        with self.assertRaises(m.DoTCanaryError):
            m.parse_a(packet, 0x1234)
        packet = struct.pack(">HHHHHH", 0x1235, 0x8180, 1, 0, 0, 0) + req[12:]
        with self.assertRaises(m.DoTCanaryError):
            m.parse_a(packet, 0x1234)

    def test_fail_on_unsafe_name_compression(self):
        with self.assertRaises(m.DoTCanaryError):
            m.dns_name_end(b"\xc0", 0)
        with self.assertRaises(m.DoTCanaryError):
            m.dns_name_end(b"\x40", 0)

    def test_is_not_a_public_listener(self):
        import inspect
        script = inspect.getsource(m.run_canary)
        self.assertIn('("127.0.0.1", 8853)', script)
        self.assertNotIn('("0.0.0.0", 853)', script)


if __name__ == "__main__":
    unittest.main()
