#!/usr/bin/env python3
"""Offline tests for RU188 :853 personal SNI direct cutover script."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/mnebydns-ru188-853-direct-personal-20261127.sh"

SAMPLE_CONF = """# RU188 stream config
map $ssl_preread_server_name $mnebydns_ru853_target {
    dns.mnebyvpn.site 10.66.77.1:8854;
    "~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.1:8854;
    default s1_mtproxy;
}
server { listen 993; listen [::]:993; proxy_pass s1_mtproxy; }
server { listen 995; listen [::]:995; proxy_pass s1_mtproxy; }
server { listen 465; listen [::]:465; proxy_pass s1_mtproxy; }
server {
    listen 853 so_keepalive=30s:10s:3;
    listen [::]:853 so_keepalive=30s:10s:3;
    ssl_preread on;
    proxy_pass $mnebydns_ru853_target;
    proxy_connect_timeout 6s;
    proxy_timeout 1h;
    proxy_socket_keepalive on;
    tcp_nodelay on;
}
"""


def _make_cert(tmpdir: Path) -> Path:
    cert = tmpdir / "cert.pem"
    key = tmpdir / "key.pem"
    ext = tmpdir / "ext.cnf"
    ext.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=dns.mnebyvpn.site\n"
        "[v3]\nsubjectAltName=DNS:dns.mnebyvpn.site,DNS:*.dns.mnebyvpn.site\n",
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
    return cert


class _LoopbackDoTServer:
    """Minimal local DoT responder with SNI inspection for offline verification."""

    def __init__(self, cert: Path, key: Path, *, allow_unknown: bool = False):
        self.allow_unknown = allow_unknown
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        self.sni_seen: list[str | None] = []

        def on_sni(sock, server_name, _ctx):
            sock._test_sni = server_name

        self.ctx.sni_callback = on_sni
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
                sni = getattr(tls, "_test_sni", None)
                self.sni_seen.append(sni)
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
                qid = query[:2]
                question = query[12:]
                if sni == "000000000000.dns.mnebyvpn.site" and not self.allow_unknown:
                    # REFUSED (rcode=5), 0 answers
                    resp = struct.pack("!2sHHHHH", qid, 0x8185, 1, 0, 0, 0) + question
                else:
                    # NOERROR, 1 A record 93.184.216.34
                    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
                    resp = struct.pack("!2sHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + ans
                tls.sendall(struct.pack("!H", len(resp)) + resp)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


class RU188DirectPersonalTests(unittest.TestCase):
    def test_bash_syntax_and_self_test(self) -> None:
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        res = subprocess.run(["bash", str(SCRIPT), "--self-test"], capture_output=True, text=True, check=True)
        self.assertIn("RU188_853_DIRECT_SELFTEST=PASS", res.stdout)

    def test_non_root_refused_with_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (td / "id").write_text("#!/bin/sh\necho 1000\n", encoding="utf-8")
            (td / "id").chmod(0o755)
            env = dict(os.environ, PATH=f"{td}{os.pathsep}{os.environ['PATH']}")
            for cmd in ("stage", "switch", "revert", "finalize", "status"):
                res = subprocess.run(["bash", str(SCRIPT), cmd], env=env, capture_output=True, text=True)
                self.assertEqual(res.returncode, 2, f"{cmd} must refuse non-root")

    def _setup_env(self, td: Path, *, allow_unknown: bool = False):
        cert = _make_cert(td)
        key = td / "key.pem"
        backend = _LoopbackDoTServer(cert, key, allow_unknown=allow_unknown)
        ingress = _LoopbackDoTServer(cert, key, allow_unknown=allow_unknown)

        etc_streams = td / "etc/nginx/streams.d"
        etc_mods = td / "etc/nginx/modules-enabled"
        usr_mods = td / "usr/lib/nginx/modules"
        etc_streams.mkdir(parents=True)
        etc_mods.mkdir(parents=True)
        usr_mods.mkdir(parents=True)

        conf = etc_streams / "01-mtproxy-stdports.conf"
        conf.write_text(SAMPLE_CONF, encoding="utf-8")
        conf.chmod(0o600)
        relay = etc_streams / "00-mtproxy-relay.conf"
        relay.write_text("upstream s1_mtproxy { server 127.0.0.1:9443; }\n", encoding="utf-8")
        (etc_mods / "50-mod-stream.conf").write_text("load_module modules/ngx_stream_module.so;\n", encoding="utf-8")
        (usr_mods / "ngx_stream_module.so").write_bytes(b"ELF")

        root = td / "opt/mnebydns-ru188-853-direct-20261127"
        bin_dir = td / "bin"
        bin_dir.mkdir()
        log_file = td / "commands.log"
        timer_flag = td / "timer.active"

        (bin_dir / "id").write_text("#!/bin/sh\n[ \"$1\" = \"-u\" ] && echo 0 && exit 0\nexit 1\n", encoding="utf-8")
        (bin_dir / "ip").write_text(
            "#!/bin/sh\necho '2: tg-relay    inet 10.66.77.2/24 scope global tg-relay'\n",
            encoding="utf-8",
        )
        (bin_dir / "nginx").write_text(
            f'#!/bin/sh\necho "nginx $*" >> "{log_file}"\n'
            'if [ "$1" = "-t" ] && [ "$2" = "-c" ]; then\n'
            '  grep -Fq "load_module" "$3" || exit 1\n'
            '  grep -Fq "10.66.77.2:8858;" "$3" || exit 1\n'
            'fi\nexit 0\n',
            encoding="utf-8",
        )
        (bin_dir / "systemd-run").write_text(
            f'#!/bin/sh\necho "systemd-run $*" >> "{log_file}"\n'
            f'touch "{timer_flag}"\nexit 0\n',
            encoding="utf-8",
        )
        (bin_dir / "systemctl").write_text(
            f'#!/bin/sh\necho "systemctl $*" >> "{log_file}"\n'
            f'if [ "$1" = "is-active" ]; then\n'
            f'  case "$*" in *nginx.service*) exit 0 ;; *.timer*) [ -f "{timer_flag}" ]; exit $? ;; esac\n'
            f'  exit 1\n'
            f'fi\n'
            f'if [ "$1" = "stop" ]; then rm -f "{timer_flag}"; exit 0; fi\n'
            f'exit 0\n',
            encoding="utf-8",
        )
        for p in bin_dir.iterdir():
            p.chmod(0o755)

        env = dict(os.environ)
        env.update({
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "SSL_CERT_FILE": str(cert),
            "MNEBYDNS_RU188_CONF": str(conf),
            "MNEBYDNS_RU188_RELAY_CONF": str(relay),
            "MNEBYDNS_RU188_MOD_STREAM_CONF": str(etc_mods / "50-mod-stream.conf"),
            "MNEBYDNS_RU188_STREAM_MODULE": str(usr_mods / "ngx_stream_module.so"),
            "MNEBYDNS_RU188_ROOT": str(root),
            "MNEBYDNS_RU188_SCRIPT": str(root / "manage.sh"),
            "MNEBYDNS_RU188_CANARY_PID": str(td / "canary.pid"),
            "MNEBYDNS_RU188_PERSONAL_HOST": "127.0.0.1",
            "MNEBYDNS_RU188_PERSONAL_PORT": str(backend.port),
            "MNEBYDNS_RU188_PROBE_ADDRS": "127.0.0.1",
            "MNEBYDNS_RU188_PROBE_PORT": str(ingress.port),
        })
        return env, conf, root, log_file, timer_flag, backend, ingress

    def test_stage_switch_status_finalize_and_revert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, conf, root, log_file, timer_flag, backend, ingress = self._setup_env(td)
            try:
                p_stage = subprocess.run(["bash", str(SCRIPT), "stage"], env=env, capture_output=True, text=True)
                self.assertEqual(p_stage.returncode, 0, p_stage.stderr)
                self.assertIn("RU188_853_DIRECT_STAGED=PASS", p_stage.stdout)
                self.assertEqual(stat.S_IMODE((root / "original.conf").stat().st_mode), 0o600)
                self.assertIn("load_module", (root / "canary.conf").read_text(encoding="utf-8"))

                p_switch = subprocess.run(["bash", str(SCRIPT), "switch"], env=env, capture_output=True, text=True)
                self.assertEqual(p_switch.returncode, 0, p_switch.stderr)
                self.assertIn("RU188_853_DIRECT_SWITCHED=PASS", p_switch.stdout)
                self.assertTrue(timer_flag.exists(), "Auto-revert timer must remain armed until finalize")

                new_text = conf.read_text(encoding="utf-8")
                self.assertIn('"~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.2:8858;', new_text)
                self.assertIn("dns.mnebyvpn.site 10.66.77.1:8854;", new_text)
                self.assertIn("default s1_mtproxy;", new_text)
                self.assertEqual(stat.S_IMODE(conf.stat().st_mode), 0o600)
                for port in ("993", "995", "465", "853"):
                    self.assertIn(f"listen {port}", new_text)

                logs = log_file.read_text(encoding="utf-8")
                self.assertIn("--unit=mnebydns-ru188-853-direct-revert-", logs)
                self.assertIn("--on-active=180", logs)
                self.assertIn("systemctl reload nginx", logs)

                p_status = subprocess.run(["bash", str(SCRIPT), "status"], env=env, capture_output=True, text=True)
                self.assertEqual(p_status.returncode, 0, p_status.stderr)
                self.assertIn("RU188_853_DIRECT_PERSONAL_TARGET=10.66.77.2:8858", p_status.stdout)

                p_fin = subprocess.run(["bash", str(SCRIPT), "finalize"], env=env, capture_output=True, text=True)
                self.assertEqual(p_fin.returncode, 0, p_fin.stderr)
                self.assertIn("RU188_853_DIRECT_FINALIZED=PASS", p_fin.stdout)
                self.assertFalse(timer_flag.exists(), "finalize must disarm auto-revert timer")
                self.assertTrue((root / "confirmed").is_file())

                p_rev = subprocess.run(["bash", str(SCRIPT), "revert"], env=env, capture_output=True, text=True)
                self.assertEqual(p_rev.returncode, 0, p_rev.stderr)
                self.assertIn("RU188_853_DIRECT_REVERTED=PASS", p_rev.stdout)
                self.assertEqual(conf.read_text(encoding="utf-8"), SAMPLE_CONF)
            finally:
                backend.close()
                ingress.close()

    def test_switch_auto_reverts_when_unknown_sni_not_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, conf, root, _log, timer_flag, backend, ingress = self._setup_env(td, allow_unknown=True)
            try:
                # Stage succeeds only if backend rejects unknown SNI; force allow_unknown after stage.
                backend.allow_unknown = False
                ingress.allow_unknown = False
                subprocess.run(["bash", str(SCRIPT), "stage"], env=env, check=True, capture_output=True)

                # Allow unknown on ingress only, so pre-switch backend passes and post-switch ingress probe fails.
                ingress.allow_unknown = True
                p_switch = subprocess.run(["bash", str(SCRIPT), "switch"], env=env, capture_output=True, text=True)
                self.assertNotEqual(p_switch.returncode, 0)
                self.assertEqual(conf.read_text(encoding="utf-8"), SAMPLE_CONF, "Auto-revert must restore original config")
                self.assertFalse(timer_flag.exists(), "Auto-revert must disarm timer after restoring")
            finally:
                backend.close()
                ingress.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
