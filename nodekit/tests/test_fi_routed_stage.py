import sys
import unittest
from pathlib import Path
from unittest.mock import patch,Mock
import ssl
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_routed_stage import phase,denied_proxy

class RoutedProbeTests(unittest.TestCase):
    @patch("fi_routed_stage.time.sleep")
    def test_transient_retried(self,sleep):
        f=Mock(side_effect=[TimeoutError(),None])
        phase("test",f,attempts=3)
        self.assertEqual(f.call_count,2)
        sleep.assert_called_once()
    @patch("fi_routed_stage.time.sleep")
    def test_wrong_answer_not_retried(self,sleep):
        f=Mock(side_effect=ValueError("route_A_not_FI"))
        with self.assertRaises(ValueError):phase("test",f,attempts=3)
        f.assert_called_once()
        sleep.assert_not_called()
    @patch("fi_routed_stage.time.sleep")
    def test_certificate_error_not_retried(self,sleep):
        f=Mock(side_effect=ssl.SSLCertVerificationError())
        with self.assertRaises(ssl.SSLCertVerificationError):phase("test",f,attempts=3)
        f.assert_called_once()
        sleep.assert_not_called()
    @patch("fi_routed_stage.socket.create_connection")
    def test_missing_proxy_not_success(self,connect):
        connect.side_effect=ConnectionRefusedError()
        with self.assertRaises(ConnectionRefusedError):denied_proxy()
    @patch("fi_routed_stage.ssl.create_default_context")
    @patch("fi_routed_stage.socket.create_connection")
    def test_unknown_sni_timeout_not_success(self,connect,context):
        context.return_value.wrap_socket.side_effect=TimeoutError()
        with self.assertRaises(TimeoutError):denied_proxy()
    @patch("fi_routed_stage.ssl.create_default_context")
    @patch("fi_routed_stage.socket.create_connection")
    def test_unknown_sni_eof_denied(self,connect,context):
        context.return_value.wrap_socket.side_effect=ssl.SSLEOFError()
        denied_proxy()
