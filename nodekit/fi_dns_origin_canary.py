#!/usr/bin/env python3
"""FI217 local CoreDNS TLS canary, compatible with an already active AWG node.

Starts ONLY a temporary 127.0.0.1:8853 child with the already approved
root-only staged Corefile. Never listens on public 853/443, edits systemd,
makes customer grants or touches the running VPN. Always kills the child.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

NODE = "fi-test-01"
ROOT = Path("/var/lib/mnebyvpn-nodekit") / NODE
COREDNS = Path("/opt/coredns/coredns")
HOSTS = ("aaaaaaaaaaaa.fi.dns.mnebyvpn.site",
         "bbbbbbbbbbbb.fi.dns.mnebyvpn.site")
PORT = 8853
QUERY = "fi-dns-canary.invalid"


class FiDnsOriginError(ValueError):
    pass


def require_file(path: Path, limit=120_000) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FiDnsOriginError("Missing pinned private FI DNS file")
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o077 or not 1 <= st.st_size <= limit:
        raise FiDnsOriginError("Untrusted FI DNS file")
    return path.read_bytes()


def prepare() -> Path:
    if os.geteuid() != 0:
        raise FiDnsOriginError("Root required")
    manifest = json.loads(require_file(ROOT / "manifest.json"))
    dns = json.loads(require_file(ROOT / "dns-proxy/manifest.json"))
    components = json.loads(require_file(ROOT / "components-manifest.json"))
    if (manifest.get("node_id") != NODE or
            manifest.get("advertise_host") != "fi.mnebyvpn.site" or
            manifest.get("state") not in ("active", "testing") or
            dns.get("node_id") != NODE or dns.get("state") != "staged" or
            dns.get("route_count") != 0 or
            dns.get("personal_dns_enabled") is not False or
            dns.get("activation_enabled") is not False):
        raise FiDnsOriginError("FI staged CoreDNS config not approved")
    expected_hash = components.get("binaries", {}).get("coredns", {}).get("sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise FiDnsOriginError("Missing pinned CoreDNS executable hash")
    if (not COREDNS.is_file() or COREDNS.is_symlink() or
            hashlib.sha256(COREDNS.read_bytes()).hexdigest() != expected_hash):
        raise FiDnsOriginError("CoreDNS binary is not approved")
    core = ROOT / "dns-proxy/Corefile"
    data = require_file(core)
    if (hashlib.sha256(data).hexdigest() !=
            dns.get("config_sha256", {}).get("Corefile")):
        raise FiDnsOriginError("Staged CoreDNS content drift")
    content = data.decode("ascii")
    if ("tls://.:8853 {" not in content or
            "  bind 127.0.0.1" not in content or
            "  forward . tls://1.1.1.1 tls://1.0.0.1 {" not in content or
            "  tls " + str(ROOT / "tls/fullchain.pem") not in content or
            " 0.0.0.0" in content):
        raise FiDnsOriginError("CoreDNS loopback-only invariants lost")
    require_file(ROOT / "tls/fullchain.pem")
    require_file(ROOT / "tls/privkey.pem")
    # The host's current CA trust and real TLS chain are verified at handshake.
    return core


def query_bytes(id_: int) -> bytes:
    labels = QUERY.split(".")
    qname = b"".join(bytes([len(s)]) + s.encode("ascii")
                     for s in labels) + b"\0"
    return struct.pack("!HHHHHH", id_, 0x0100, 1, 0, 0, 0) + qname + b"\0\1\0\1"


def read_exact(stream, amount: int) -> bytes:
    result = bytearray()
    while len(result) < amount:
        data = stream.recv(amount - len(result))
        if not data:
            raise FiDnsOriginError("CoreDNS closed DoT socket")
        result.extend(data)
    return bytes(result)


def dot_probe(hostname: str) -> bool:
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    except OSError as exc:
        raise FiDnsOriginError("Local TCP connect failed") from exc
    with raw:
        try:
            tls = context.wrap_socket(raw, server_hostname=hostname)
        except ssl.SSLCertVerificationError as exc:
            raise FiDnsOriginError("FI regional TLS certificate trust failed") from exc
        except ssl.SSLError as exc:
            allow = {
                "TLSV1_ALERT_INTERNAL_ERROR": "tls_remote_internal_alert",
                "SSLV3_ALERT_HANDSHAKE_FAILURE": "tls_peer_handshake_alert",
                "TLSV1_ALERT_UNKNOWN_CA": "tls_peer_unknown_ca",
                "UNEXPECTED_EOF_WHILE_READING": "tls_peer_closed_early",
                "SSLV3_ALERT_BAD_CERTIFICATE": "tls_peer_bad_certificate",
                "WRONG_VERSION_NUMBER": "tls_wrong_version",
            }
            reason = allow.get(getattr(exc, "reason", None))
            if reason:
                raise FiDnsOriginError("FI TLS signal: " + reason) from exc
            raise FiDnsOriginError("FI regional TLS handshake rejected") from exc
        with tls:
            tls.settimeout(5)
            if tls.version() not in ("TLSv1.2", "TLSv1.3"):
                raise FiDnsOriginError("Unsupported TLS")
            names = tls.getpeercert().get("subjectAltName", ())
            if ("DNS", "*.fi.dns.mnebyvpn.site") not in names:
                raise FiDnsOriginError("FI-specific wildcard SAN missing")
            query = query_bytes(0x4a71)
            try:
                tls.sendall(struct.pack("!H", len(query)) + query)
                n = struct.unpack("!H", read_exact(tls, 2))[0]
                if not 12 < n <= 4096:
                    raise FiDnsOriginError("Invalid DoT reply frame")
                answer = read_exact(tls, n)
            except (TimeoutError, socket.timeout) as exc:
                raise FiDnsOriginError("Local DoT DNS answer timeout") from exc
            ident, flags, qd, count, _, _ = struct.unpack("!HHHHHH", answer[:12])
            if (ident != 0x4a71 or not flags & 0x8000 or flags & 0xF or
                    qd != 1 or count <= 0 or
                    answer[12:len(query)] != query[12:]):
                raise FiDnsOriginError("CoreDNS failed independent A question")
            return True


def local_test_corefile(original: Path, directory: Path) -> Path:
    """Derive ephemeral local A answer, preserving pinned TLS/loopback config.

    No forwarder, signed production policy or origin Corefile is edited.
    The synthetic .invalid domain cannot be mistaken for a customer route.
    """
    text = original.read_text("ascii")
    marker = "  forward . tls://1.1.1.1 tls://1.0.0.1 {"
    if text.count(marker) != 1:
        raise FiDnsOriginError("Unsupported staged forwarder")
    template = (
        "  template IN A . {\n"
        r"    match ^fi-dns-canary\.invalid\.$" + "\n"
        '    answer "{{ .Name }} 5 IN A 192.0.2.1"\n'
        "    fallthrough\n"
        "  }\n"
    )
    result = directory / "Corefile"
    result.write_text(text.replace(marker, template + marker), encoding="ascii")
    result.chmod(0o600)
    return result


def run() -> dict:
    core = prepare()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.bind(("127.0.0.1", PORT))
    # Temporary root-only Corefile is a derivative of the approved stage.
    # This tests the REAL CoreDNS TLS listener and DNS message parser without
    # depending on the external Cloudflare upstream's current connectivity.
    with tempfile.TemporaryDirectory(
        prefix=".fi-dns-test-", dir=ROOT
    ) as temp:
        test_conf = local_test_corefile(core, Path(temp))
        child = subprocess.Popen([str(COREDNS), "-conf", str(test_conf)],
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            results = {}
            for host in HOSTS:
                for attempt in range(12):
                    if child.poll() is not None:
                        raise FiDnsOriginError("CoreDNS child exited")
                    try:
                        results[host] = dot_probe(host)
                        break
                    except FiDnsOriginError as error:
                        # Only a startup TCP-bind race warrants retries.
                        # TLS/DNS failures must be classified and not masked.
                        if str(error) != "Local TCP connect failed" or attempt == 11:
                            raise
                        time.sleep(0.5)
            if not all(results.values()):
                raise FiDnsOriginError("FI regional DoT probe denied")
            return {"fi_dns_origin_local_canary": "PASS",
                    "two_distinct_regional_tls_names": True,
                    "dns_local_a_answer_verified": True,
                    "external_upstream_verified": False,
                    "public_port_opened": False,
                    "customer_grant_issued": False,
                    "awg_changed": False}
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True))
        return 0
    except FiDnsOriginError as exc:
        # Only static, non-secret categories; never print CoreDNS config/key.
        known = {
            "Root required": "root_required",
            "Missing pinned private FI DNS file": "missing_file",
            "Untrusted FI DNS file": "file_permissions",
            "FI staged CoreDNS config not approved": "stage_state",
            "Missing pinned CoreDNS executable hash": "binary_pin_absent",
            "CoreDNS binary is not approved": "binary_pin_mismatch",
            "Staged CoreDNS content drift": "corefile_drift",
            "CoreDNS loopback-only invariants lost": "unsafe_corefile",
            "Unsupported staged forwarder": "forwarder_mismatch",
            "CoreDNS child exited": "coredns_start_failed",
            "CoreDNS local TLS/DoT unavailable": "local_tls_unavailable",
            "Local TCP connect failed": "loopback_connect_failed",
            "FI regional TLS handshake rejected": "tls_handshake_failed",
            "FI regional TLS certificate trust failed": "tls_ca_chain_untrusted",
            "FI TLS signal: tls_remote_internal_alert": "tls_remote_internal_alert",
            "FI TLS signal: tls_peer_handshake_alert": "tls_peer_handshake_alert",
            "FI TLS signal: tls_peer_unknown_ca": "tls_peer_unknown_ca",
            "FI TLS signal: tls_peer_closed_early": "tls_peer_closed_early",
            "FI TLS signal: tls_peer_bad_certificate": "tls_peer_bad_certificate",
            "FI TLS signal: tls_wrong_version": "tls_wrong_version",
            "Local DoT DNS answer timeout": "dns_response_timeout",
            "Invalid DoT reply frame": "invalid_dns_frame",
            "Unsupported TLS": "unsupported_tls",
            "FI regional DoT probe denied": "regional_dot_denied",
            "CoreDNS failed independent A question": "local_dns_answer_failed",
            "FI-specific wildcard SAN missing": "regional_wildcard_missing",
        }
        print("FI_DNS_LOOPBACK_BLOCKER=" +
              known.get(str(exc), "uncategorized"), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, ssl.SSLError,
            subprocess.SubprocessError):
        print("FI_DNS_LOOPBACK_BLOCKER=runtime_or_tls_error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
