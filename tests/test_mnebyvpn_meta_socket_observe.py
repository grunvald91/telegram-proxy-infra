"""Regression test: inbound REALITY client peers must not become Meta destinations."""
import importlib.util
from pathlib import Path
import tempfile
from unittest import TestCase, mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/mnebyvpn-meta-socket-observe.py"
spec = importlib.util.spec_from_file_location("meta_socket_observe", SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

def row(index, local, remote, state, inode):
    return (f"{index}: {local} {remote} {state} 00000000:00000000 "
            f"00:00000000 00000000 0 0 {inode} 1 00000000\n")

class OutboundClassificationTest(TestCase):
    def test_exclude_inbound_reality_socket_and_keep_true_https_outbound(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "net").mkdir()
            (root / "net" / "tcp").write_text(
                "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
                # Client -> server REALITY 2053, remote is an ephemeral source port.
                + row(0, "00000000:0805", "04030201:C350", "01", 111)
                # Server -> remote HTTPS endpoint (157.240.18.63:443).
                + row(1, "0A00000A:9C40", "3F12F09D:01BB", "01", 222)
                # TCP SYN_SENT is not an established destination.
                + row(2, "0A00000A:9C41", "3F12F09D:01BB", "02", 333)
            )
            for name in ("tcp6", "udp", "udp6"):
                (root / "net" / name).write_text("header\n")
            with mock.patch.object(collector, "socket_inodes", return_value={"111", "222", "333"}):
                result = collector.proc_sockets(999, root)
            self.assertEqual(result, {("tcp", "157.240.18.63", 443)})

    def test_no_outbound_if_only_subscriber_ingress(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "net").mkdir()
            (root / "net" / "tcp").write_text(
                "header\n" + row(0, "00000000:0805", "04030201:C350", "01", 111)
            )
            for name in ("tcp6", "udp", "udp6"):
                (root / "net" / name).write_text("header\n")
            with mock.patch.object(collector, "socket_inodes", return_value={"111"}):
                self.assertEqual(collector.proc_sockets(999, root), set())
