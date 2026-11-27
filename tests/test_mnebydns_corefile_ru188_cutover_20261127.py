#!/usr/bin/env python3
"""Offline tests for RU188 Corefile cutover helper, apply script, and mobileconfig."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import plistlib
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER_PY = ROOT / "scripts/mnebydns-corefile-ru188-cutover-20261127.py"
APPLY_SH = ROOT / "scripts/mnebydns-corefile-ru188-apply-20261127.sh"
REAL_GUARD = ROOT / "scripts/mnebydns_dns_policy_guard.py"

spec = importlib.util.spec_from_file_location("corefile_ru188_cutover", HELPER_PY)
assert spec and spec.loader
cutover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cutover)

MOBILECONFIG_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
\t<key>PayloadIdentifier</key>
\t<string>site.mnebyvpn.dns.profile</string>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.dnsSettings.managed</string>
\t\t\t<key>DNSSettings</key>
\t\t\t<dict>
\t\t\t\t<key>DNSProtocol</key>
\t\t\t\t<string>TLS</string>
\t\t\t\t<key>ServerName</key>
\t\t\t\t<string>dns.mnebyvpn.site</string>
\t\t\t\t<key>ServerAddresses</key>
\t\t\t\t<array>
\t\t\t\t\t<string>89.125.90.101</string>
\t\t\t\t</array>
\t\t\t</dict>
\t\t</dict>
\t</array>
</dict>
</plist>
"""


def build_synthetic_corefile(main_a_count: int = 621) -> str:
    """Build a 3-block Corefile mirroring DE89 production structure (623 total A rules)."""
    parts = [
        "tls://.:853 {\n",
        "    bind 89.125.90.101\n",
        "    reload 5s 1s\n",
        "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n",
    ]
    named_hosts = [
        "www.youtube.com", "claude.ai", "api.openai.com", "chatgpt.com",
        "x.com", "www.tiktok.com", "gemini.google.com", "play.googleapis.com",
    ]
    for i in range(main_a_count):
        host = named_hosts[i] if i < len(named_hosts) else f"host{i}.example.net"
        ttl = 30 if i == 1 else (20 if i % 2 == 0 else 45)
        indent = "    " if i % 3 else "\t"
        parts.append(
            f"{indent}template IN A {host} {{\n"
            f"{indent}    match ^{host.replace('.', '[.]')}[.]$\n"
            f'{indent}    answer "{{{{ .Name }}}} {ttl} IN A 89.125.90.101"\n'
            f"{indent}    fallthrough\n"
            f"{indent}}}\n"
        )
    parts.extend([
        "    template IN AAAA . {\n",
        "        match ^www[.]youtube[.]com[.]$\n",
        "        rcode NOERROR\n",
        "    }\n",
        "    template IN HTTPS . {\n",
        "        match ^www[.]youtube[.]com[.]$\n",
        "        rcode NOERROR\n",
        "    }\n",
        "    # FI217 exit anchor 217.11.167.91\n",
        "    forward . tls://9.9.9.9 tls://149.112.112.112 {\n",
        "        tls_servername dns.quad9.net\n",
        "    }\n",
        "}\n",
        "tls://stun.l.google.com:853 tls://stun1.l.google.com:853 {\n",
        "    bind 89.125.90.101\n",
        "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n",
        "    template IN A {\n",
        '        answer "{{ .Name }} 20 IN A 89.125.90.101"\n',
        "    }\n",
        "    forward . tls://9.9.9.9 tls://149.112.112.112 {\n",
        "        tls_servername dns.quad9.net\n",
        "    }\n",
        "}\n",
        "tls://www.google.com:853 tls://generativelanguage.googleapis.com:853 {\n",
        "    bind 89.125.90.101\n",
        "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n",
        "    template IN A {\n",
        "        match ^www[.]google[.]com[.]$\n",
        '        answer "{{ .Name }} 20 IN A 89.125.90.101"\n',
        "    }\n",
        "}\n",
    ])
    return "".join(parts)


def _make_cert(tmpdir: Path) -> tuple[Path, Path]:
    cert = tmpdir / "cert.pem"
    key = tmpdir / "key.pem"
    ext = tmpdir / "ext.cnf"
    ext.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=dns.mnebyvpn.site\n"
        "[v3]\nsubjectAltName=DNS:dns.mnebyvpn.site\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2",
            "-config", str(ext),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _parse_qname_and_qtype(query: bytes) -> tuple[str, int]:
    pos = 12
    labels = []
    while pos < len(query):
        ln = query[pos]
        pos += 1
        if ln == 0:
            break
        labels.append(query[pos : pos + ln].decode("ascii"))
        pos += ln
    qtype = struct.unpack_from("!H", query, pos)[0]
    return ".".join(labels), qtype


def _dns_reply_for(query: bytes, mapped_ip: str) -> bytes:
    qid = query[:2]
    qname, qtype = _parse_qname_and_qtype(query)
    question = query[12:]
    if qtype == 1 and qname in cutover.PREFLIGHT_MAPPED_HOSTS:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 20, 4) + socket.inet_aton(mapped_ip)
        return struct.pack("!2sHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + ans
    if qtype in (28, 65) and qname in cutover.PREFLIGHT_MAPPED_HOSTS:
        return struct.pack("!2sHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
    if qtype == 1 and qname in cutover.PREFLIGHT_DIRECT_HOSTS:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
        return struct.pack("!2sHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + ans
    return struct.pack("!2sHHHHH", qid, 0x8180, 1, 0, 0, 0) + question


class _DynamicDoTServer:
    """Loopback DoT server reading live Corefile to simulate CoreDNS hot reload."""

    def __init__(self, cert: Path, key: Path, corefile_path: Path):
        self.corefile_path = corefile_path
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                tls = self.ctx.wrap_socket(conn, server_side=True)
            except OSError:
                return
            with tls:
                try:
                    hdr = tls.recv(2)
                    if len(hdr) < 2:
                        return
                    length = struct.unpack("!H", hdr)[0]
                    query = b""
                    while len(query) < length:
                        chunk = tls.recv(length - len(query))
                        if not chunk:
                            return
                        query += chunk
                except OSError:
                    return
                text = self.corefile_path.read_text(encoding="utf-8")
                mapped = "188.120.254.223" if "IN A 188.120.254.223" in text else "89.125.90.101"
                resp = _dns_reply_for(query, mapped)
                tls.sendall(struct.pack("!H", len(resp)) + resp)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


class CorefileRU188CutoverTests(unittest.TestCase):
    def test_syntax_and_self_tests(self) -> None:
        subprocess.run(["bash", "-n", str(APPLY_SH)], check=True)
        subprocess.run([sys.executable, "-m", "py_compile", str(HELPER_PY)], check=True)
        r1 = subprocess.run([sys.executable, str(HELPER_PY), "--self-test"], capture_output=True, text=True, check=True)
        self.assertIn("COREFILE_RU188_CUTOVER_SELFTEST=PASS", r1.stdout)
        r2 = subprocess.run(["bash", str(APPLY_SH), "--self-test"], capture_output=True, text=True, check=True)
        self.assertIn("COREFILE_RU188_CUTOVER_SELFTEST=PASS", r2.stdout)

    def test_rewrite_multiblock_622_lines_and_bind_invariants(self) -> None:
        core = build_synthetic_corefile(621)
        rewritten, stats = cutover.rewrite_corefile(core)
        self.assertEqual(stats["rewritten_a_count"], 623)
        self.assertEqual(stats["bind_de_count"], 3)
        self.assertEqual(stats["server_blocks"], 3)
        self.assertEqual(stats["fi217_count"], 1)
        self.assertEqual(rewritten.count("    bind 89.125.90.101\n"), 3)
        self.assertEqual(rewritten.count('answer "{{ .Name }} 30 IN A 188.120.254.223"'), 1)
        self.assertEqual(rewritten.count('answer "{{ .Name }} 20 IN A 188.120.254.223"'), 313)
        self.assertEqual(rewritten.count('answer "{{ .Name }} 45 IN A 188.125.90.101"'), 0)
        self.assertEqual(rewritten.count('answer "{{ .Name }} 45 IN A 188.120.254.223"'), 309)
        self.assertIn("template IN A {\n", rewritten)
        self.assertIn("forward . tls://9.9.9.9 tls://149.112.112.112 {", rewritten)
        self.assertIn("reload 5s 1s\n", rewritten)

    def test_rewrite_rejects_under_minimum_or_missing_bind(self) -> None:
        small = build_synthetic_corefile(4)
        with self.assertRaises(ValueError):
            cutover.rewrite_corefile(small)  # default min_rewrites=600
        no_bind = small.replace("    bind 89.125.90.101\n", "")
        with self.assertRaises(ValueError):
            cutover.rewrite_corefile(no_bind, min_rewrites=1)

    def test_preflight_converts_all_three_blocks_and_preserves_forward_tls(self) -> None:
        rewritten, _ = cutover.rewrite_corefile(build_synthetic_corefile(11), min_rewrites=12)
        pf = cutover.make_preflight_corefile(rewritten, preflight_port=18553, preflight_bind="127.0.0.1")
        self.assertIn(".:18553 {", pf)
        self.assertIn("stun.l.google.com:18553 stun1.l.google.com:18553 {", pf)
        self.assertIn("www.google.com:18553 generativelanguage.googleapis.com:18553 {", pf)
        self.assertEqual(pf.count("bind 127.0.0.1"), 3)
        self.assertNotIn("bind 89.125.90.101", pf)
        self.assertNotIn("tls://.:853", pf)
        self.assertNotIn("/run/credentials/", pf)
        self.assertNotIn("reload 5s 1s", pf)
        self.assertIn("forward . tls://9.9.9.9 tls://149.112.112.112 {", pf)
        self.assertIn("template IN A {", pf)

    def test_mobileconfig_update_and_plist_validation(self) -> None:
        updated, info = cutover.update_mobileconfig(MOBILECONFIG_SAMPLE)
        self.assertEqual(info["server_addresses"], ["188.120.254.223"])
        self.assertEqual(info["server_name"], "dns.mnebyvpn.site")
        parsed = plistlib.loads(updated.encode("utf-8"))
        self.assertEqual(parsed["PayloadContent"][0]["DNSSettings"]["ServerAddresses"], ["188.120.254.223"])
        self.assertNotIn("89.125.90.101", updated)
        with self.assertRaises(ValueError):
            cutover.update_mobileconfig(updated)

    def test_real_repo_guard_compatibility(self) -> None:
        info = cutover.validate_guard_module(REAL_GUARD)
        self.assertEqual(info, {"resolver_bind": "89.125.90.101", "pin": "188.120.254.223"})

    def _setup_lifecycle_env(self, td: Path, *, change_pid_on_reload: bool = False):
        cert, key = _make_cert(td)
        core_dir = td / "opt/mnebydns-dot"
        nginx_dir = td / "etc/nginx"
        proxy_dir = td / "etc/mnebydns-googlepilot"
        maint_dir = td / "opt/mnebydns-maintenance"
        www_dir = td / "var/www/cdn-servgo"
        ckpt_root = td / "opt/mnebydns-stable-checkpoints"
        stale_ckpt = ckpt_root / "1795547449"
        state_dir = td / "opt/mnebydns-corefile-ru188-20261127"
        bin_dir = td / "bin"
        for d in (core_dir, nginx_dir, proxy_dir, maint_dir, www_dir, stale_ckpt, bin_dir):
            d.mkdir(parents=True)

        corefile = core_dir / "Corefile"
        corefile.write_text(build_synthetic_corefile(621), encoding="utf-8")
        corefile.chmod(0o640)

        nginx_conf = nginx_dir / "nginx.conf"
        nginx_conf.write_text("events {}\nstream { server { listen 443; proxy_pass 127.0.0.1:9443; } }\n", encoding="utf-8")
        proxy_conf = proxy_dir / "nginx.conf"
        proxy_conf.write_text("events {}\nstream { server { listen 127.0.0.1:15449; proxy_pass 127.0.0.1:443; } }\n", encoding="utf-8")

        mobileconfig = www_dir / "mnebyvpn-dns.mobileconfig"
        mobileconfig.write_text(MOBILECONFIG_SAMPLE, encoding="utf-8")
        mobileconfig.chmod(0o644)

        # Stale 1795547449 checkpoint intentionally does NOT match live Corefile.
        (stale_ckpt / "dns.stable").write_text("STALE_OLD_COREFILE\n", encoding="utf-8")
        (stale_ckpt / "nginx.stable").write_text(nginx_conf.read_text(encoding="utf-8"), encoding="utf-8")
        (stale_ckpt / "proxy.stable").write_text(proxy_conf.read_text(encoding="utf-8"), encoding="utf-8")
        (ckpt_root / "current").write_text(str(stale_ckpt) + "\n", encoding="utf-8")

        dot_server = _DynamicDoTServer(cert, key, corefile)

        # Live guard initially pinned to 89.125.90.101; staged guard uses real guard structure + loopback DoT port.
        guard_live = maint_dir / "mnebydns_dns_policy_guard.py"
        guard_live.write_text('RESOLVER_BIND = "89.125.90.101"\nPIN = "89.125.90.101"\ndef smoke_check(): return {"all_pinned": True}\n', encoding="utf-8")
        guard_live.chmod(0o644)

        guard_staged = td / "staged_guard.py"
        guard_staged.write_text(
            f"""import ipaddress, socket, ssl, struct, secrets
RESOLVER_BIND = "89.125.90.101"
PIN = "188.120.254.223"
DOT_TLS_NAME = "dns.mnebyvpn.site"
PROTECTED_A = ("www.youtube.com", "claude.ai", "www.google.com")
def dns_a(host, *, address="127.0.0.1", timeout=4.0):
    qid = secrets.randbits(16)
    qname = b"".join(bytes([len(s)]) + s.encode() for s in host.split(".")) + b"\\x00"
    msg = struct.pack("!HHHHHH", qid, 0x100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    with socket.create_connection(("127.0.0.1", {dot_server.port}), timeout=timeout) as c:
        with ssl.create_default_context().wrap_socket(c, server_hostname=DOT_TLS_NAME) as t:
            t.sendall(struct.pack("!H", len(msg)) + msg)
            sz = struct.unpack("!H", t.recv(2))[0]
            resp = b""
            while len(resp) < sz:
                resp += t.recv(sz - len(resp))
    return [str(ipaddress.IPv4Address(resp[-4:]))]
def smoke_check():
    for h in PROTECTED_A:
        if dns_a(h) != [PIN]:
            raise RuntimeError("Mismatch for " + h)
    return {{"protected_hosts_checked": len(PROTECTED_A), "expected_ipv4": PIN, "all_pinned": True}}
""",
            encoding="utf-8",
        )

        # Mock safe_deploy script verifying checkpoint + positional `status`!
        safe_deploy = maint_dir / "mnebydns_safe_deploy.py"
        safe_deploy_log = td / "safe_deploy.log"
        safe_deploy.write_text(
            f"""#!/usr/bin/env python3
import hashlib, json, pathlib, subprocess, sys
pathlib.Path({str(safe_deploy_log)!r}).open("a").write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:] != ["status"]:
    raise SystemExit("Unexpected args: " + repr(sys.argv[1:]))
ptr = pathlib.Path({str(ckpt_root / 'current')!r}).read_text().strip()
cp = pathlib.Path(ptr)
subprocess.run(["sha256sum", "-c", "stable-manifest.sha256"], cwd=cp, check=True, capture_output=True)
assert (cp / "dns.stable").read_bytes() == pathlib.Path({str(corefile)!r}).read_bytes()
assert (cp / "nginx.stable").read_bytes() == pathlib.Path({str(nginx_conf)!r}).read_bytes()
assert (cp / "proxy.stable").read_bytes() == pathlib.Path({str(proxy_conf)!r}).read_bytes()
print(json.dumps({{
    "read_only": True,
    "checkpoint": ptr,
    "dns_reader_group_verified": True,
    "services": {{
        "dns": {{"service_active": True, "tcp_listener": True}},
        "pilot": {{"service_active": True, "tcp_listener": True}},
        "shared": {{"service_active": True, "tcp_listener": True}},
    }},
}}))
""",
            encoding="utf-8",
        )
        safe_deploy.chmod(0o755)

        # Pick free TCP port for preflight plain DNS mock CoreDNS server.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            preflight_port = s.getsockname()[1]

        coredns_bin = core_dir / "coredns"
        coredns_bin.write_text(
            f"""#!/usr/bin/env python3
import pathlib, socket, struct, sys
if sys.argv[1:] == ["-plugins"]:
    print("dns.reload\\ndns.forward\\ndns.cache")
    sys.exit(0)
if len(sys.argv) == 3 and sys.argv[1] == "-conf":
    conf = pathlib.Path(sys.argv[2]).read_text()
    assert ".:{preflight_port}" in conf
    assert "stun.l.google.com:{preflight_port}" in conf
    assert "www.google.com:{preflight_port}" in conf
    assert "bind 127.0.0.1" in conf
    assert "bind 89.125.90.101" not in conf
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", {preflight_port}))
    sock.listen(16)
    MAPPED = {repr(set(cutover.PREFLIGHT_MAPPED_HOSTS))}
    DIRECT = {repr(set(cutover.PREFLIGHT_DIRECT_HOSTS))}
    def parse_q(q):
        pos = 12
        lbls = []
        while pos < len(q):
            ln = q[pos]; pos += 1
            if ln == 0: break
            lbls.append(q[pos:pos+ln].decode())
            pos += ln
        return ".".join(lbls), struct.unpack_from("!H", q, pos)[0]
    while True:
        c, _ = sock.accept()
        with c:
            hdr = c.recv(2)
            if len(hdr) < 2:
                continue
            sz = struct.unpack("!H", hdr)[0]
            q = b""
            while len(q) < sz:
                chunk = c.recv(sz - len(q))
                if not chunk:
                    break
                q += chunk
            if len(q) < sz:
                continue
            qn, qt = parse_q(q)
            qid, question = q[:2], q[12:]
            if qt == 1 and qn in MAPPED:
                ans = b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 20, 4) + socket.inet_aton("188.120.254.223")
                r = struct.pack("!2sHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + ans
            elif qt in (28, 65) and qn in MAPPED:
                r = struct.pack("!2sHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
            elif qt == 1 and qn in DIRECT:
                ans = b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
                r = struct.pack("!2sHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + ans
            else:
                r = struct.pack("!2sHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
            c.sendall(struct.pack("!H", len(r)) + r)
""",
            encoding="utf-8",
        )
        coredns_bin.chmod(0o755)

        timer_flag = td / "timer.active"
        cmd_log = td / "cmd.log"
        pid_counter = td / "pid_calls"
        pid_counter.write_text("0", encoding="utf-8")

        (bin_dir / "id").write_text('#!/bin/sh\n[ "$1" = "-u" ] && echo 0 && exit 0\nexit 1\n', encoding="utf-8")
        (bin_dir / "nginx").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (bin_dir / "systemd-run").write_text(
            f'#!/bin/sh\necho "systemd-run $*" >> "{cmd_log}"\ntouch "{timer_flag}"\nexit 0\n',
            encoding="utf-8",
        )
        (bin_dir / "ss").write_text(
            f"""#!/usr/bin/env python3
import socket, sys
s = socket.socket()
try:
    s.connect(("127.0.0.1", {preflight_port}))
    print("LISTEN 0 128 127.0.0.1:{preflight_port} 0.0.0.0:*")
except OSError:
    pass
finally:
    s.close()
""",
            encoding="utf-8",
        )
        (bin_dir / "systemctl").write_text(
            f"""#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
pathlib.Path({str(cmd_log)!r}).open("a").write("systemctl " + " ".join(args) + "\\n")
tf = pathlib.Path({str(timer_flag)!r})
pc = pathlib.Path({str(pid_counter)!r})
if args[0] == "is-active":
    quiet = "--quiet" in args
    if args[-1].endswith(".timer"):
        ok = tf.exists()
    else:
        ok = True
    if not quiet:
        print("active" if ok else "inactive")
    sys.exit(0 if ok else 1)
if args[0] == "stop":
    tf.unlink(missing_ok=True)
    sys.exit(0)
if args[0] == "show" and "MainPID" in args:
    n = int(pc.read_text()) + 1
    pc.write_text(str(n))
    if {change_pid_on_reload!r} and n >= 2:
        print("99999")
    else:
        print("12345")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        for p in bin_dir.iterdir():
            p.chmod(0o755)

        env = dict(os.environ)
        env.update({
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "SSL_CERT_FILE": str(cert),
            "MNEBYDNS_CUTOVER_STATE_DIR": str(state_dir),
            "MNEBYDNS_CUTOVER_SCRIPT": str(state_dir / "apply.sh"),
            "MNEBYDNS_CUTOVER_HELPER": str(HELPER_PY),
            "MNEBYDNS_CUTOVER_COREDNS_BIN": str(coredns_bin),
            "MNEBYDNS_CUTOVER_COREFILE": str(corefile),
            "MNEBYDNS_CUTOVER_NGINX_CONF": str(nginx_conf),
            "MNEBYDNS_CUTOVER_PROXY_CONF": str(proxy_conf),
            "MNEBYDNS_CUTOVER_GUARD_LIVE": str(guard_live),
            "MNEBYDNS_CUTOVER_GUARD_STAGED": str(guard_staged),
            "MNEBYDNS_CUTOVER_MOBILECONFIG": str(mobileconfig),
            "MNEBYDNS_CUTOVER_CHECKPOINT_ROOT": str(ckpt_root),
            "MNEBYDNS_CUTOVER_SAFE_DEPLOY": str(safe_deploy),
            "MNEBYDNS_CUTOVER_LOCK": str(td / "cutover.lock"),
            "MNEBYDNS_CUTOVER_PREFLIGHT_PORT": str(preflight_port),
            "MNEBYDNS_CUTOVER_DOT_PORT": str(dot_server.port),
            "MNEBYDNS_CUTOVER_DOT_ADDR": "127.0.0.1",
            "MNEBYDNS_CUTOVER_RELOAD_WAIT_TRIES": "5",
            "MNEBYDNS_CUTOVER_RELOAD_WAIT_SLEEP": "0.05",
        })
        return (
            env, state_dir, corefile, guard_live, mobileconfig,
            ckpt_root, stale_ckpt, timer_flag, cmd_log, safe_deploy_log, dot_server,
        )

    def test_stage_with_real_repo_guard_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, state_dir, *_rest, dot_server = self._setup_lifecycle_env(td)
            try:
                env["MNEBYDNS_CUTOVER_GUARD_STAGED"] = str(REAL_GUARD)
                res = subprocess.run(["bash", str(APPLY_SH), "stage"], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertIn("COREFILE_RU188_STAGED=PASS", res.stdout)
                self.assertTrue((state_dir / "Corefile.candidate").is_file())
                self.assertEqual(
                    (state_dir / "guard.candidate.py").read_text(encoding="utf-8"),
                    REAL_GUARD.read_text(encoding="utf-8"),
                )
            finally:
                dot_server.close()

    def test_full_stage_apply_status_finalize_and_revert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (
                env, state_dir, corefile, guard_live, mobileconfig,
                ckpt_root, stale_ckpt, timer_flag, cmd_log, safe_deploy_log, dot_server,
            ) = self._setup_lifecycle_env(td)
            try:
                p_stage = subprocess.run(["bash", str(APPLY_SH), "stage"], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(p_stage.returncode, 0, p_stage.stderr)
                self.assertIn("COREFILE_RU188_STAGED=PASS", p_stage.stdout)

                p_apply = subprocess.run(["bash", str(APPLY_SH), "apply"], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(p_apply.returncode, 0, p_apply.stderr)
                self.assertIn("COREFILE_RU188_AUTO_REVERT=ARMED_5M", p_apply.stdout)
                self.assertIn("COREFILE_RU188_APPLIED=PENDING_FINALIZE", p_apply.stdout)
                self.assertTrue(timer_flag.exists())

                self.assertEqual(stat.S_IMODE(corefile.stat().st_mode), 0o640)
                core_text = corefile.read_text(encoding="utf-8")
                self.assertEqual(core_text.count("IN A 188.120.254.223"), 623)
                self.assertEqual(core_text.count("IN A 89.125.90.101"), 0)
                self.assertEqual(core_text.count("    bind 89.125.90.101\n"), 3)

                mc_parsed = plistlib.loads(mobileconfig.read_bytes())
                self.assertEqual(mc_parsed["PayloadContent"][0]["DNSSettings"]["ServerAddresses"], ["188.120.254.223"])
                self.assertIn('PIN = "188.120.254.223"', guard_live.read_text(encoding="utf-8"))

                logs = cmd_log.read_text(encoding="utf-8")
                self.assertIn("--on-active=5m", logs)

                p_status = subprocess.run(["bash", str(APPLY_SH), "status"], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(p_status.returncode, 0, p_status.stderr)
                self.assertIn("COREFILE_RU188_RU_A_ANSWERS=623", p_status.stdout)
                self.assertIn("COREFILE_RU188_DE_A_ANSWERS=0", p_status.stdout)
                self.assertIn("COREFILE_RU188_DE_BINDS=3", p_status.stdout)

                p_fin = subprocess.run(["bash", str(APPLY_SH), "finalize"], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(p_fin.returncode, 0, p_fin.stderr)
                self.assertIn("COREFILE_RU188_FINALIZED=PASS", p_fin.stdout)
                self.assertFalse(timer_flag.exists(), "finalize must disarm auto-revert timer")
                self.assertTrue((state_dir / "confirmed").is_file())

                ptr_target = Path((ckpt_root / "current").read_text(encoding="utf-8").strip())
                self.assertNotEqual(ptr_target, stale_ckpt, "stale 1795547449 checkpoint must be superseded")
                self.assertTrue(ptr_target.is_dir())
                subprocess.run(["sha256sum", "-c", "stable-manifest.sha256"], cwd=ptr_target, check=True, capture_output=True)
                self.assertEqual((ptr_target / "dns.stable").read_text(encoding="utf-8"), core_text)
                self.assertIn("status", safe_deploy_log.read_text(encoding="utf-8"))

                p_rev = subprocess.run(["bash", str(APPLY_SH), "revert"], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(p_rev.returncode, 0, p_rev.stderr)
                self.assertIn("COREFILE_RU188_REVERTED=PASS", p_rev.stdout)
                self.assertEqual(corefile.read_text(encoding="utf-8").count("IN A 89.125.90.101"), 623)
                self.assertEqual(
                    plistlib.loads(mobileconfig.read_bytes())["PayloadContent"][0]["DNSSettings"]["ServerAddresses"],
                    ["89.125.90.101"],
                )
            finally:
                dot_server.close()

    def test_apply_auto_reverts_if_coredns_pid_changes_during_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (
                env, _state_dir, corefile, guard_live, mobileconfig,
                _ckpt_root, _stale_ckpt, timer_flag, _cmd_log, _sd_log, dot_server,
            ) = self._setup_lifecycle_env(td, change_pid_on_reload=True)
            try:
                subprocess.run(["bash", str(APPLY_SH), "stage"], env=env, check=True, capture_output=True, timeout=15)
                p_apply = subprocess.run(["bash", str(APPLY_SH), "apply"], env=env, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(p_apply.returncode, 0)
                self.assertEqual(corefile.read_text(encoding="utf-8").count("IN A 89.125.90.101"), 623)
                self.assertIn('PIN = "89.125.90.101"', guard_live.read_text(encoding="utf-8"))
                self.assertEqual(
                    plistlib.loads(mobileconfig.read_bytes())["PayloadContent"][0]["DNSSettings"]["ServerAddresses"],
                    ["89.125.90.101"],
                )
                self.assertFalse(timer_flag.exists())
            finally:
                dot_server.close()

    def test_finalize_fails_closed_when_safe_deploy_returns_done_false_exit_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (
                env, state_dir, _corefile, _guard_live, _mobileconfig,
                _ckpt_root, _stale_ckpt, timer_flag, _cmd_log, _sd_log, dot_server,
            ) = self._setup_lifecycle_env(td)
            try:
                subprocess.run(["bash", str(APPLY_SH), "stage"], env=env, check=True, capture_output=True, timeout=15)
                subprocess.run(["bash", str(APPLY_SH), "apply"], env=env, check=True, capture_output=True, timeout=15)
                self.assertTrue(timer_flag.exists())

                safe_deploy = Path(env["MNEBYDNS_CUTOVER_SAFE_DEPLOY"])
                safe_deploy.write_text(
                    '#!/usr/bin/env python3\nimport json\n'
                    'print(json.dumps({"done": False, "error": "RuntimeError", "reason": "Corefile must be 0640"}))\n',
                    encoding="utf-8",
                )
                safe_deploy.chmod(0o755)

                p_fin = subprocess.run(["bash", str(APPLY_SH), "finalize"], env=env, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(p_fin.returncode, 0)
                self.assertFalse((state_dir / "confirmed").exists())
                self.assertTrue(timer_flag.exists(), "Auto-revert timer must remain armed when safe_deploy reports done=false")
            finally:
                dot_server.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
