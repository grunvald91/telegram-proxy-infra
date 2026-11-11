"""Offline test fixtures for the DoT stability sampler and failure criteria."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import meta_v14_dot_stability as m

class StabilityContracts(unittest.TestCase):
    def test_status_is_explicit_and_never_hidden(self):
        self.assertEqual(m.status("RCODE0_A_DE1_A_RU0"), "RCODE_0")
        self.assertEqual(m.status("RCODE2_A_DE0_A_RU0"), "RCODE_2")
        self.assertEqual(m.status("TimeoutError"), "TimeoutError")
        self.assertEqual(m.status("arbitrary"), "BAD_RESPONSE")

    def test_stable_cases_are_green(self):
        with patch.object(m, "ROUNDS", 2), patch.object(m, "DELAY_S", 0), \
             patch.object(m, "sample", return_value="RCODE_0"), \
             redirect_stdout(StringIO()) as output:
            code = m.run()
        self.assertEqual(code, 0)
        self.assertIn("dns_v14_repeated_failure_count=0", output.getvalue())

    def test_repeated_servfail_is_not_reported_as_stable(self):
        def synthetic(domain, typ, target, tls_host):
            if domain == "i.instagram.com" and typ == 1 and target == m.DE_PUBLIC:
                return "RCODE_2"
            return "RCODE_0"
        with patch.object(m, "ROUNDS", 2), patch.object(m, "DELAY_S", 0), \
             patch.object(m, "sample", side_effect=synthetic), \
             redirect_stdout(StringIO()) as output:
            code = m.run()
        self.assertEqual(code, 1)
        self.assertIn("dns_v14_error_edge_i_instagram_com_A_RCODE_2=2", output.getvalue())
        self.assertIn("dns_v14_repeated_failure_count=1", output.getvalue())

    def test_one_transient_failure_is_reported(self):
        n = [0]
        def synthetic(domain, typ, target, tls_host):
            n[0] += 1
            return "TimeoutError" if n[0] == 1 else "RCODE_0"
        with patch.object(m, "ROUNDS", 3), patch.object(m, "DELAY_S", 0), \
             patch.object(m, "sample", side_effect=synthetic), \
             redirect_stdout(StringIO()) as output:
            code = m.run()
        self.assertEqual(code, 0)
        self.assertIn("INTERMITTENT", output.getvalue())

if __name__ == "__main__":
    unittest.main()
