#!/usr/bin/env python3
"""Isolated network-namespace integration test for Geneva dup-ACK (badsum).

Runs completely rootless inside `unshare -Urn` (or as root):
- Spawns a child netns for the TLS client (`198.18.0.2`) connected via veth to
  the server netns (`198.18.0.1`).
- Loads `nft_geneva_rules` on the server netns, runs a local TLS echo backend,
  `WindowProxy(..., clamp_window=False)`, and `NetfilterQueueWorker(queue_num=211)`.
- Captures all Ethernet frames on the client veth via AF_PACKET and verifies:
  1. Genuine SYN+ACK with valid TCP checksum is delivered.
  2. Geneva duplicate ACK(s) with valid IPv4 checksum and CORRUPTED TCP checksum
     arrive on the client interface (`egress_dupack_badsum >= 2`).
  3. Full standard TLSv1.3 handshake + payload transfer succeeds cleanly.
"""
from __future__ import annotations

import hashlib
import os
import selectors
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meta_geneva_dupack import (
    GENEVA_QUEUE,
    GenevaEgressVerifier,
    NetfilterQueueWorker,
    nft_geneva_rules,
    verify_ipv4_tcp_checksum,
)
from meta_v15_receive_window import WindowProxy
from meta_v31_sni_evidence import CaptureEvidence, validate_geneva_report

EDGE = "198.18.0.1"
PEER = "198.18.0.2"
HOST = "i.instagram.com"
PAYLOAD = b"geneva-dupack-tls-integrity-check\n" * 1024
ENV_PATH = f"/usr/sbin:/sbin:{os.environ.get('PATH', '')}"


def run_cmd(argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PATH=ENV_PATH)
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
        env=env,
    )


def make_self_signed_cert(cert_dir: Path) -> tuple[Path, Path]:
    cert = cert_dir / "server.crt"
    key = cert_dir / "server.key"
    run_cmd(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            f"/CN={HOST}",
            "-addext",
            f"subjectAltName=DNS:{HOST}",
        ]
    )
    return cert, key


def run_tls_backend(cert: Path, key: Path, stop: threading.Event, ready: threading.Event) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 19443))
    srv.listen(8)
    srv.settimeout(0.2)
    ready.set()
    try:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    buf = bytearray()
                    while len(buf) < len(PAYLOAD):
                        chunk = tls.recv(65536)
                        if not chunk:
                            break
                        buf.extend(chunk)
                    tls.sendall(hashlib.sha256(bytes(buf)).digest())
    finally:
        srv.close()


def client_process_main(
    cert_path: str,
    ready_fd: int,
    go_fd: int,
    done_fd: int,
    exit_fd: int,
    result_file: str,
) -> int:
    """Runs inside the client network namespace."""
    os.write(ready_fd, b"R")
    os.close(ready_fd)
    # Wait until parent moves v1 into this netns and signals go.
    os.read(go_fd, 1)
    os.close(go_fd)

    run_cmd(["ip", "link", "set", "lo", "up"])
    run_cmd(["ip", "link", "set", "v1", "up"])
    run_cmd(["ip", "addr", "add", f"{PEER}/24", "dev", "v1"])
    # Disable TSO/GSO on v1 so TLS ClientHello (>1500B on OpenSSL 3.5) is wire-segmented at MTU 1500.
    run_cmd(["ethtool", "-K", "v1", "tso", "off", "gso", "off"])

    # Capture raw Ethernet frames on client v1 to verify wire packets.
    pkt_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    pkt_sock.bind(("v1", 0))
    pkt_sock.setblocking(False)

    verifier = GenevaEgressVerifier(edge=EDGE)
    synack_valid_sum = 0
    stop_cap = threading.Event()

    def drain_capture() -> None:
        sel = selectors.DefaultSelector()
        sel.register(pkt_sock, selectors.EVENT_READ)
        try:
            while not stop_cap.is_set():
                for key, _ in sel.select(timeout=0.05):
                    while True:
                        try:
                            frame = key.fileobj.recv(65535)
                        except BlockingIOError:
                            break
                        verifier.ethernet(frame)
                        if len(frame) >= 54 and frame[12:14] == b"\x08\x00":
                            ip_pkt = frame[14:]
                            ihl = (ip_pkt[0] & 0x0F) * 4
                            if ip_pkt[9] == 6 and len(ip_pkt) >= ihl + 20:
                                flags = ip_pkt[ihl + 13]
                                if (flags & 0x12) == 0x12:
                                    ok, _, _ = verify_ipv4_tcp_checksum(ip_pkt)
                                    if ok:
                                        nonlocal synack_valid_sum
                                        synack_valid_sum += 1
        finally:
            sel.close()

    cap_thread = threading.Thread(target=drain_capture, daemon=True)
    cap_thread.start()
    time.sleep(0.05)

    ctx = ssl.create_default_context(cafile=cert_path)
    with socket.create_connection((EDGE, 443), timeout=10, source_address=(PEER, 0)) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as tls:
            assert tls.getpeercert()
            tls.sendall(PAYLOAD)
            digest = b""
            while len(digest) < 32:
                part = tls.recv(32 - len(digest))
                if not part:
                    raise AssertionError("truncated TLS echo")
                digest += part
            assert digest == hashlib.sha256(PAYLOAD).digest()

    time.sleep(0.15)
    stop_cap.set()
    cap_thread.join(timeout=2)
    pkt_sock.close()

    snap = verifier.snapshot()
    Path(result_file).write_text(
        f"synack_valid={synack_valid_sum}\n"
        f"egress_synack={snap['egress_synack']}\n"
        f"egress_synack_badsum={snap['egress_synack_badsum']}\n"
        f"egress_dupack_badsum={snap['egress_dupack_badsum']}\n"
        f"egress_dupack_valid_sum={snap['egress_dupack_valid_sum']}\n"
        f"egress_rst_badsum={snap['egress_rst_badsum']}\n"
        f"egress_rst_valid_sum={snap['egress_rst_valid_sum']}\n",
        encoding="utf-8",
    )
    os.write(done_fd, b"D")
    os.close(done_fd)
    # Keep client netns (and server veth v0) alive until parent stops tcpdump.
    os.read(exit_fd, 1)
    os.close(exit_fd)
    return 0


def run_netns_test(variant: str = "ack-exact") -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Run inside `unshare -Urn` or as root")

    with tempfile.TemporaryDirectory(prefix="geneva-netns-") as tmp:
        tmp_dir = Path(tmp)
        cert, key = make_self_signed_cert(tmp_dir)
        result_file = tmp_dir / "client_result.txt"

        r_ready, w_ready = os.pipe()
        r_go, w_go = os.pipe()
        r_done, w_done = os.pipe()
        r_exit, w_exit = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r_ready)
            os.close(w_go)
            os.close(r_done)
            os.close(w_exit)
            os.unshare(getattr(os, "CLONE_NEWNET", 0x40000000))
            rc = client_process_main(str(cert), w_ready, r_go, w_done, r_exit, str(result_file))
            os._exit(rc)

        os.close(w_ready)
        os.close(r_go)
        os.close(w_done)
        os.close(r_exit)
        assert os.read(r_ready, 1) == b"R"
        os.close(r_ready)

        run_cmd(["ip", "link", "set", "lo", "up"])
        run_cmd(["ip", "link", "add", "v0", "type", "veth", "peer", "name", "v1"])
        run_cmd(["ip", "link", "set", "v1", "netns", str(pid)])
        run_cmd(["ip", "link", "set", "v0", "up"])
        run_cmd(["ip", "addr", "add", f"{EDGE}/24", "dev", "v0"])
        run_cmd(["ethtool", "-K", "v0", "gro", "off", "lro", "off"])

        stop_backend = threading.Event()
        backend_ready = threading.Event()
        backend_thread = threading.Thread(
            target=run_tls_backend,
            args=(cert, key, stop_backend, backend_ready),
            daemon=True,
        )
        backend_thread.start()
        assert backend_ready.wait(3)

        proxy = WindowProxy(
            EDGE,
            PEER,
            port=18443,
            backend=("127.0.0.1", 19443),
            clamp_window=False,
        )
        nfq = NetfilterQueueWorker(queue_num=GENEVA_QUEUE, variant=variant, repeats=2)
        proxy.start()
        nfq.start()
        evidence = None
        if shutil.which("tcpdump"):
            argv = [
                "tcpdump",
                "-i",
                "v0",
                "-n",
                "-U",
                "--immediate-mode",
                "-s",
                "1600",
                "-w",
                "-",
                f"ip and tcp and host {EDGE} and port 443 and host {PEER}",
            ]
            with patch("meta_v31_sni_evidence.capture_command", return_value=argv):
                evidence = CaptureEvidence(
                    PEER,
                    tmp_dir / f"evidence-{variant}.json",
                    geneva_egress=True,
                    geneva_stats_fn=nfq.snapshot,
                )
            evidence.egress_verifier = GenevaEgressVerifier(edge=EDGE)
            evidence.sink.egress_verifier = evidence.egress_verifier
            evidence.start()
        rules = nft_geneva_rules(
            EDGE,
            PEER,
            port=18443,
            interface="v0",
            table="mneby_geneva_netns",
            queue_num=GENEVA_QUEUE,
        )
        try:
            run_cmd(["nft", "-f", "-"], input_text=rules)
            os.write(w_go, b"G")
            os.close(w_go)
            assert os.read(r_done, 1) == b"D"
            os.close(r_done)
            if evidence is not None:
                time.sleep(0.1)
                evidence.stop()
                report = evidence.publish(proxy.stats)
                assert report["capture_ok"], report
                verdict = validate_geneva_report(report)
                assert report["kernel_drops"] == 0, report
                assert report["geneva_metrics"]["egress_dupack_badsum"] == 2, report["geneva_metrics"]
                assert report["stats"]["target_clienthello"] == 1, report["stats"]
                print(
                    f"variant={variant} tcpdump_evidence={verdict} "
                    f"drops={report['kernel_drops']} geneva_metrics={report['geneva_metrics']}",
                    flush=True,
                )
            os.close(w_exit)
            _, status = os.waitpid(pid, 0)
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise AssertionError(f"client netns failed with status {status}")
        finally:
            try:
                os.close(w_exit)
            except OSError:
                pass
            if evidence is not None:
                evidence.stop()
            run_cmd(["nft", "delete", "table", "inet", "mneby_geneva_netns"])
            nfq.stop()
            proxy.close()
            stop_backend.set()
            backend_thread.join(timeout=2)

        client_metrics = dict(
            line.split("=", 1) for line in result_file.read_text(encoding="utf-8").splitlines() if "=" in line
        )
        nfq_stats = nfq.snapshot()
        print(f"variant={variant} client={client_metrics} nfq={nfq_stats}", flush=True)
        assert nfq_stats["synack_seen"] >= 1, nfq_stats
        expected_sent = 4 if variant == "synack-rst-badsum" else 2
        assert nfq_stats["dupack_sent"] >= expected_sent, nfq_stats
        assert nfq_stats["send_errors"] == 0, nfq_stats
        assert int(client_metrics["synack_valid"]) >= 1, client_metrics
        if variant == "synack-rst-badsum":
            assert int(client_metrics["egress_synack_badsum"]) >= 2, client_metrics
            assert int(client_metrics["egress_rst_badsum"]) >= 2, client_metrics
        elif variant == "rst-badseq":
            assert int(client_metrics["egress_rst_valid_sum"]) >= 2, client_metrics
        else:
            assert int(client_metrics["egress_dupack_badsum"]) == nfq_stats["dupack_sent"] == 2, client_metrics
        assert proxy.stats["target_sni"] == 1, proxy.stats


if __name__ == "__main__":
    for mode in ("ack-exact", "ack-desync", "synack-rst-badsum", "rst-badseq"):
        run_netns_test(mode)
    print("GENEVA_DUPACK_NETNS_TEST=PASS", flush=True)
