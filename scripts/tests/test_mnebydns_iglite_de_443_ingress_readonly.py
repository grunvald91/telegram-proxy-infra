"""Offline synthetic tcpdump header parser tests, never open sockets."""
import importlib.util
from pathlib import Path
import unittest

file = Path(__file__).resolve().parents[1] / "mnebydns_iglite_de_443_ingress_readonly.py"
spec = importlib.util.spec_from_file_location("observer", file)
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
P = "198.51.100.9"


def line(src, dst, flags, size):
    return ("16:20:01.000 eth0 In IP " + src + " > " + dst
            + ": Flags [" + flags + "], seq 10, ack 11, win 65535, length " + str(size))


class HeaderObserverTests(unittest.TestCase):
    def test_complete_handshake_and_client_tls_payload_counted(self):
        sample="\n".join((
            line(P+".47111",o.DE+".443","S",0),
            line(o.DE+".443",P+".47111","S.",0),
            line(P+".47111",o.DE+".443",".",0),
            line(P+".47111",o.DE+".443","P.",4),
            line(P+".47111",o.DE+".443","P.",212),
            line(o.DE+".443",P+".47111",".",0),
        ))
        result=o.parse_summary(sample,P)
        self.assertEqual(result["syn"],1)
        self.assertEqual(result["synack"],1)
        self.assertEqual(result["ack_inbound"],3)
        self.assertEqual(result["data_inbound"],2)
        self.assertEqual(result["first_data_bytes"],4)
        self.assertEqual(result["rst_inbound"],0)

    def test_other_clients_and_ports_are_not_counted(self):
        sample="\n".join((
            line("198.51.100.10.47111",o.DE+".443","S",0),
            line(P+".47111",o.DE+".853","S",0),
            line(P+".47111",o.DE+".80","S",0),
            line(o.DE+".443","198.51.100.10.47111","S.",0),
        ))
        result=o.parse_summary(sample,P)
        self.assertEqual(result["syn"],0)
        self.assertEqual(result["synack"],0)
        self.assertIsNone(result["first_data_bytes"])

    def test_rst_and_empty_are_distinguishable(self):
        result=o.parse_summary(line(P+".55555",o.DE+".443","R.",0),P)
        self.assertEqual(result["rst_inbound"],1)
        self.assertEqual(result["data_inbound"],0)
        self.assertEqual(o.parse_summary("",P)["syn"],0)

if __name__ == "__main__":
    unittest.main()
