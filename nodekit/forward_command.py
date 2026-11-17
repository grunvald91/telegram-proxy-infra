#!/usr/bin/env python3
"""Root-only SSH entrypoint: forward exactly one SIGNED controller command.

SSH owns authentication/encryption; the local Xray supervisor independently
verifies the Ed25519 signature, node binding, entitlement and revision.
No private controller key, shell command, TCP listener or audit output here.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

NODE = re.compile(r"[a-z0-9][a-z0-9-]{2,39}")
MAX_REQUEST = 4096
MAX_RESPONSE = 8192


class TransportError(ValueError):
    pass


def deliver(node_id: str, payload: bytes, *, run_root: Path = Path(
        "/run/mnebyvpn-nodekit"), socket_factory=socket.socket,
        require_root: bool = True) -> bytes:
    if require_root and os.geteuid() != 0:
        raise TransportError("Root-only control channel")
    if not isinstance(node_id, str) or not NODE.fullmatch(node_id) or node_id.endswith("-"):
        raise TransportError("Invalid node identifier")
    if (not isinstance(payload, bytes) or len(payload) > MAX_REQUEST or
            not payload.endswith(b"\n") or payload.count(b"\n") != 1):
        raise TransportError("Controller command size/newline invalid")
    try:
        request = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise TransportError("Malformed signed command") from exc
    if not isinstance(request, dict) or request.get("nodeId") != node_id:
        raise TransportError("Command targets a different node")
    location = run_root / node_id / "control.sock"
    if run_root.is_symlink() or location.parent.is_symlink():
        raise TransportError("Control runtime symlink forbidden")
    for folder in (run_root, location.parent):
        st = folder.stat()
        if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022 or (
                require_root and st.st_uid != 0):
            raise TransportError("Untrusted control socket directory")
    status = location.lstat()
    if not stat.S_ISSOCK(status.st_mode) or status.st_mode & 0o777 != 0o600:
        raise TransportError("Unsafe control socket")
    if require_root and status.st_uid != 0:
        raise TransportError("Control socket must be owned by root")
    with socket_factory(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(location))
        conn.sendall(payload)
        output = bytearray()
        while len(output) <= MAX_RESPONSE:
            chunk = conn.recv(4096)
            if not chunk:
                break
            output.extend(chunk)
            if b"\n" in chunk:
                break
    if len(output) > MAX_RESPONSE or not output.endswith(b"\n"):
        raise TransportError("Local supervisor response invalid or too long")
    answer = json.loads(output)
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        raise TransportError("Local supervisor rejected signed command")
    return bytes(output)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--node-id", required=True)
    args = ap.parse_args()
    try:
        # OpenSSH authorized_keys must force this exact command while the
        # client intentionally requests "false". Unrestricted SSH root keys
        # are not an acceptable controller provisioning transport.
        if os.environ.get("SSH_ORIGINAL_COMMAND") != "false":
            raise TransportError("Restricted forced-command SSH key required")
        request = sys.stdin.buffer.read(MAX_REQUEST + 2)
        result = deliver(args.node_id, request)
        sys.stdout.buffer.write(result)
        sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError, TypeError):
        # Do not echo the signed command, secret credentials or remote paths.
        print("nodekit_delivery_error=FAIL_CLOSED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
