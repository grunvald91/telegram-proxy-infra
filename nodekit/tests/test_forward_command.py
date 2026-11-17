"""Root-only command bridge: UNIX framing, permissions and node binding."""
import importlib.util
from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

NODEKIT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nodekit_forward",
                                               NODEKIT / "forward_command.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(4097)
        message = json.loads(raw)
        self.wfile.write(json.dumps(
            {"ok": True, "result": {"node_id": message["nodeId"],
                                    "revision": 1}}).encode() + b"\n")


class ForwardCommandTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name) / "run"
        self.root.mkdir()
        self.node = "de-test-node"
        node_dir = self.root / self.node
        node_dir.mkdir(mode=0o700)
        self.location = node_dir / "control.sock"
        self.server = socketserver.UnixStreamServer(str(self.location), Handler)
        self.addCleanup(self.server.server_close)
        self.location.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)

    def test_forwards_one_command_with_no_data_in_log(self):
        body = json.dumps({"nodeId": self.node, "op": "inspect"}) + "\n"
        result = m.deliver(self.node, body.encode(),
                           run_root=self.root, require_root=False)
        self.assertEqual(json.loads(result)["result"]["node_id"], self.node)

    def test_rejects_foreign_node_unsafe_socket_and_bad_framing(self):
        good = json.dumps({"nodeId": self.node}) + "\n"
        for payload in [
            (json.dumps({"nodeId": "another-node"}) + "\n").encode(),
            (good[:-1]).encode(),
            b"invalid json\n", b"x" * 4096 + b"\n",
            (good + "\n").encode(),
        ]:
            with self.subTest(payload=payload[:35]), self.assertRaises(m.TransportError):
                m.deliver(self.node, payload, run_root=self.root,
                          require_root=False)
        self.root.chmod(0o777)
        with self.assertRaises(m.TransportError):
            m.deliver(self.node, good.encode(), run_root=self.root,
                      require_root=False)
        self.root.chmod(0o755)
        self.location.chmod(0o666)
        with self.assertRaises(m.TransportError):
            m.deliver(self.node, good.encode(), run_root=self.root,
                      require_root=False)


    def test_cli_refuses_unrestricted_ssh_sessions(self):
        for value in (None, "", "python3 forward_command.py", "true"):
            variables = {} if value is None else {"SSH_ORIGINAL_COMMAND": value}
            with self.subTest(original=value), patch.dict(
                    os.environ, variables, clear=True), patch.object(
                    __import__("sys"), "argv",
                    ["forward_command.py", "--node-id", self.node]):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(m.main(), 2)


if __name__ == "__main__":
    unittest.main()
