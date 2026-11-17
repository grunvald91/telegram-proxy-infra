#!/usr/bin/env python3
"""Temporary loopback-only DNS-over-TLS canary on a NEW Nodekit VPS.

Proves valid public CA TLS and an actual DNS A response via CoreDNS.
Starts a child bound to 127.0.0.1:8853 only; always terminates it.
Does NOT open public 853/443, alter DNS policies, peers or subscriptions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time

from install_components import node_ready, safe_dir, safe_manifest, digest

ROOT = Path("/var/lib/mnebyvpn-nodekit")


class DoTCanaryError(ValueError):
    pass


def dns_wire(host: str, query_id: int) -> bytes:
    labels = host.split(".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise DoTCanaryError("Invalid DNS name")
    question = b"".join(bytes([len(label)]) + label.encode("ascii")
                        for label in labels) + b"\x00\x00\x01\x00\x01"
    return struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question


def dns_name_end(packet: bytes, offset: int) -> int:
    # Skip a DNS name, including compression pointers, without following any
    # pointers into untrusted data.
    for _ in range(128):
        if offset >= len(packet):
            raise DoTCanaryError("Truncated DNS name")
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 2 > len(packet):
                raise DoTCanaryError("Truncated DNS compression pointer")
            return offset + 2
        if length & 0xc0:
            raise DoTCanaryError("Invalid DNS name encoding")
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise DoTCanaryError("DNS name recursion bound exceeded")


def parse_a(packet: bytes, query_id: int) -> list[str]:
    if len(packet) < 12:
        raise DoTCanaryError("Truncated DNS answer")
    id_, flags, qd, an, _, _ = struct.unpack(">HHHHHH", packet[:12])
    if id_ != query_id or not flags & 0x8000 or flags & 0x000F or qd != 1:
        raise DoTCanaryError("Unrelated or failed DNS response")
    pos = dns_name_end(packet, 12)
    if pos + 4 > len(packet):
        raise DoTCanaryError("Truncated DNS question")
    pos += 4
    answers: list[str] = []
    if an > 100:
        raise DoTCanaryError("Unexpected DNS answer count")
    for _ in range(an):
        pos = dns_name_end(packet, pos)
        if pos + 10 > len(packet):
            raise DoTCanaryError("Truncated DNS RR")
        kind, klass, _, length = struct.unpack(">HHIH", packet[pos:pos + 10])
        pos += 10
        if pos + length > len(packet):
            raise DoTCanaryError("Truncated DNS RDATA")
        if kind == 1 and klass == 1 and length == 4:
            answers.append(socket.inet_ntoa(packet[pos:pos + 4]))
        pos += length
    return answers


def receive_exact(connection, amount: int) -> bytes:
    data = bytearray()
    while len(data) < amount:
        part = connection.recv(amount - len(data))
        if not part:
            raise DoTCanaryError("DNS TLS socket closed unexpectedly")
        data.extend(part)
    return bytes(data)


def dot_request(host: str, *, port: int = 8853) -> list[str]:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    query_id = secrets.randbelow(65536)
    wire = dns_wire(host, query_id)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            tls.settimeout(8)
            tls.sendall(struct.pack(">H", len(wire)) + wire)
            amount = struct.unpack(">H", receive_exact(tls, 2))[0]
            if amount < 12 or amount > 4096:
                raise DoTCanaryError("DNS TLS response length invalid")
            return parse_a(receive_exact(tls, amount), query_id)


def validate_stage(node: Path, hostname: str) -> Path:
    manifest = safe_manifest(node / "manifest.json")
    if (manifest.get("advertise_host") != hostname or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False or
            manifest.get("state") != "testing"):
        raise DoTCanaryError("Node is not an unpublished FI test")
    policy = safe_manifest(node / "dns-proxy" / "manifest.json")
    if (policy.get("state") != "staged" or
            policy.get("activation_enabled") is not False or
            policy.get("open_resolver_enabled") is not False or
            policy.get("personal_dns_enabled") is not False or
            policy.get("route_count") != 0):
        raise DoTCanaryError("DNS is not an isolated zero-route stage")
    cert = safe_manifest(node / "tls" / "manifest.json")
    if (cert.get("hostname") != hostname or
            cert.get("state") != "certificate_staged" or
            cert.get("activation_enabled") is not False):
        raise DoTCanaryError("No trusted staged certificate")
    coredns = Path("/opt/coredns/coredns")
    expected = safe_manifest(node / "components-manifest.json")["binaries"]["coredns"]["sha256"]
    if coredns.is_symlink() or not coredns.is_file() or digest(coredns) != expected:
        raise DoTCanaryError("CoreDNS binary integrity check failed")
    corefile = node / "dns-proxy" / "Corefile"
    if (corefile.is_symlink() or not corefile.is_file() or
            hashlib.sha256(corefile.read_bytes()).hexdigest() !=
            policy.get("config_sha256", {}).get("Corefile")):
        raise DoTCanaryError("CoreDNS candidate drift")
    content = corefile.read_text()
    if ("  bind 127.0.0.1" not in content or
            "tls://.:8853" not in content or
            "tls " + str(node / "tls" / "fullchain.pem") not in content):
        raise DoTCanaryError("CoreDNS is not restricted to loopback")
    return corefile


def run_canary(root: Path, node_id: str, host: str, expected_ip: str) -> dict:
    if os.geteuid() != 0 or node_id != "fi-test-01" or host != "fi.mnebyvpn.site" or (
            expected_ip != "217.11.167.91"):
        raise DoTCanaryError("Approved FI test VPS only")
    node = node_ready(root, node_id)
    corefile = validate_stage(node, host)

    # Refuse to affect an existing listener or running systemd CoreDNS.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test:
        test.bind(("127.0.0.1", 8853))
    child = subprocess.Popen(
        ["/opt/coredns/coredns", "-conf", str(corefile)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
    )
    try:
        answer = None
        for attempt in range(12):
            if child.poll() is not None:
                raise DoTCanaryError("CoreDNS failed to start")
            try:
                answer = dot_request(host)
                break
            except (OSError, ssl.SSLError) as error:
                if attempt == 11:
                    raise DoTCanaryError("CoreDNS DoT is unreachable") from error
                time.sleep(0.5)
        if answer is None or expected_ip not in answer:
            raise DoTCanaryError("CoreDNS did not return the expected new VPS IP")
        return {
            "node_id": node_id, "hostname": host,
            "tls_ca_verified": True, "tls_hostname_verified": True,
            "dot_query_verified": True, "a_record": expected_ip,
            "public_listeners_enabled": False, "published": False,
        }
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--expected-ipv4", required=True)
    parser.add_argument("--stage-root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        print(json.dumps(run_canary(args.stage_root, args.node_id,
                                    args.host, args.expected_ipv4), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, ssl.SSLError, subprocess.SubprocessError) as error:
        print("nodekit_dot_local_canary_error=" + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
