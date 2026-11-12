"""Strict offline wire fixtures for Instagram Lite DNS route verification."""
import importlib.util
from pathlib import Path
import socket
import struct
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "mnebydns_iglite_dns_wire_checks.py"
spec = importlib.util.spec_from_file_location("iglite_wire", SOURCE)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

ID = 0x7192
QNAME = w.wire_name(w.HOST)


def answer(kind, value, *, owner=b"\xc0\x0c", cls=1):
    return owner + struct.pack("!HHIH", kind, cls, 20, len(value)) + value


def response(qtype, records=(), *, tx=ID, flags=0x8180, question_name=QNAME):
    return (struct.pack("!HHHHHH", tx, flags, 1, len(records), 0, 0)
            + question_name + struct.pack("!HH", qtype, 1) + b"".join(records))


class ExactWireRoute(unittest.TestCase):
    def test_positive_exact_A_and_empty_other_types(self):
        ip = socket.inet_aton(w.EDGE)
        msg = response(w.QTYPES["A"], (answer(1, ip),))
        self.assertEqual(w.check_answer(msg, ID, w.QTYPES["A"]), "A_EXACT_DE")
        for name in ("AAAA", "HTTPS", "SVCB", "CNAME"):
            qtype = w.QTYPES[name]
            self.assertEqual(w.check_answer(response(qtype), ID, qtype),
                             "NO_ALIAS_OR_IPV6")

    def test_rejects_direct_aaaa_meta(self):
        val = socket.inet_pton(socket.AF_INET6, "2a03:2880::1")
        with self.assertRaisesRegex(ValueError, "bypass"):
            w.check_answer(response(28, (answer(28, val),)), ID, 28)

    def test_rejects_https_svcb_alias_and_cname(self):
        for name, record_kind, payload in (
            ("HTTPS", 65, b"\x00\x01\x00"),
            ("SVCB", 64, b"\x00\x01\x00"),
            ("CNAME", 5, w.wire_name("direct.instagram.com")),
        ):
            with self.subTest(kind=name), self.assertRaisesRegex(ValueError, "bypass"):
                qtype = w.QTYPES[name]
                w.check_answer(response(qtype, (answer(record_kind, payload),)), ID, qtype)

    def test_rejects_A_with_fallback_cname_or_multiple_values(self):
        expected = answer(1, socket.inet_aton(w.EDGE))
        other = answer(1, socket.inet_aton("157.240.0.160"))
        for records in (
            (expected, other), (other,),
            (answer(5, w.wire_name("direct.instagram.com")), expected),
            (),
        ):
            with self.subTest(count=len(records)), self.assertRaises(ValueError):
                w.check_answer(response(1, records), ID, 1)

    def test_wrong_transaction_qname_qtype_and_rcode_fail(self):
        exact = answer(1, socket.inet_aton(w.EDGE))
        for data in (
            response(1, (exact,), tx=ID + 1),
            response(1, (exact,), flags=0x8183),
            response(1, (exact,), flags=0x8380),
            response(1, (exact,), question_name=w.wire_name("other.instagram.com")),
            response(28, (exact,)),
        ):
            with self.subTest(data=data[:15]), self.assertRaises(ValueError):
                w.check_answer(data, ID, 1)

    def test_rejects_compressed_name_cycles_and_malformed_records(self):
        for name in (b"\xc0\x0c", b"\xc0\xff", b"\xc0"):
            with self.subTest(raw=name), self.assertRaises(ValueError):
                w.read_name(name if name == b"\xc0" else b"\x00" * 12 + name, 12)
        exact = answer(1, socket.inet_aton(w.EDGE))
        with self.assertRaises(ValueError):
            w.check_answer(response(1, (exact,))[:-1], ID, 1)

    def test_question_is_exact_and_type_constrained(self):
        for kind in w.QTYPES.values():
            data = w.make_question(kind, ID)
            self.assertEqual(struct.unpack_from("!H", data)[0], ID)
            self.assertIn(w.wire_name(w.HOST), data)
        self.assertEqual(len(w.QTYPES), 5)

if __name__ == "__main__":
    unittest.main()
