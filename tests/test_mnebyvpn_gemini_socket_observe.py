"""Offline tests for privacy-bounded MNEBYVPN Gemini socket metadata sampler."""
import importlib.util
import pathlib
import socket
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "gemini_socket_trace",ROOT/"scripts/mnebyvpn-gemini-socket-observe.py")
assert spec and spec.loader
O=importlib.util.module_from_spec(spec)
spec.loader.exec_module(O)

class SocketTracingContract(unittest.TestCase):
    def test_read_proc_ipv4_and_ipv6_addresses_and_ports(self):
        self.assertEqual(O.decode_endpoint("0100007F:01BB",socket.AF_INET),("127.0.0.1",443))
        self.assertEqual(O.decode_endpoint("08080808:0035",socket.AF_INET),("8.8.8.8",53))
        ip,port=O.decode_endpoint("00000000000000000000000001000000:01BB",socket.AF_INET6)
        self.assertEqual(ip,"::1")
        self.assertEqual(port,443)

    def test_avoid_non_global_destinations(self):
        for address in ("127.0.0.1","10.66.77.1","192.168.1.1",
                        "169.254.1.1","::1","fe80::1","fd00::1"):
            self.assertTrue(O.private_ip(address))
        self.assertFalse(O.private_ip("8.8.8.8"))
        self.assertFalse(O.private_ip("2001:4860:4860::8888"))

    def test_only_google_domain_candidates_and_aggregated_ports(self):
        observed={
            ("tcp","8.8.8.8",443),("tcp","8.8.8.8",5228),
            ("tcp","1.1.1.1",8443),
        }
        mapping={
            "jnn-pa.googleapis.com":{"8.8.8.8"},
            "www.youtube.com":{"2.2.2.2"},
        }
        result=O.summarize(observed,mapping)
        self.assertIn("new_or_existing_global_remote_socket_endpoints=3",result)
        self.assertIn("endpoints_matching_current_Google_DNS_A_AAAA=2",result)
        self.assertIn("endpoints_with_no_current_Google_DNS_match=1",result)
        self.assertIn("possible_Google_destination=jnn-pa.googleapis.com ports=tcp/443,tcp/5228",result)
        self.assertFalse(any("8.8.8.8" in line or "1.1.1.1" in line for line in result))
        self.assertIn("Google_domain_on_each_connection_proven=false",result)
        self.assertIn("HTTPS_voice_content_decrypted=false",result)

    def test_fails_closed_on_multiple_credential_state(self):
        import datetime as dt
        from types import SimpleNamespace
        now=dt.datetime(2026,11,8,13,0,tzinfo=dt.timezone.utc)
        data={
            "a":{"enabled":True,"expiresAt":"2026-11-09T13:00:00+00:00"},
            "b":{"enabled":True,"expiresAt":"2026-11-09T13:00:00+00:00"},
            "c":{"enabled":False,"expiresAt":"2026-11-09T13:00:00+00:00"},
        }
        with patch.object(O,"STATE",new=SimpleNamespace(read_text=lambda: __import__("json").dumps(data))):
            self.assertEqual(O.active_count(now),2)

    def test_no_packet_logs_secrets_or_live_service_writes(self):
        source=(ROOT/"scripts/mnebyvpn-gemini-socket-observe.py").read_text()
        for forbidden in ("tcpdump","pyshark","scapy","/dev/packet","pcap",
                          "systemctl restart","systemctl reload","subprocess.Popen",
                          "os.system(","CONFIG.write_text","STATE.write_text",
                          "key_file.read_text","xray -config"):
            self.assertNotIn(forbidden,source)
        self.assertIn("preflight_status=READY_SINGLE_ACTIVE_VPN_PROFILE",source)
        self.assertIn("capture_stopped_no_persistent_tracking=true",source)

if __name__=="__main__":
    unittest.main(verbosity=2)
