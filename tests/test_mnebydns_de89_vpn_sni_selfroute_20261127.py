#!/usr/bin/env python3
"""Offline tests for DE89 VPN SNI :443 self-route script and systemd unit."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/mnebydns-de89-vpn-sni-selfroute-20261127.sh"
UNIT = ROOT / "ops/mnebydns-vpn-sni-selfroute-20261127.service"
SOURCE = SCRIPT.read_text(encoding="utf-8")
SERVICE_TEXT = UNIT.read_text(encoding="utf-8")


def _make_cert(tmpdir: Path) -> tuple[Path, Path]:
    cert = tmpdir / "cert.pem"
    key = tmpdir / "key.pem"
    ext = tmpdir / "ext.cnf"
    ext.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=mnebyvpn.site\n"
        "[v3]\nsubjectAltName=DNS:mnebyvpn.site,DNS:www.mnebyvpn.site,DNS:www.youtube.com\n",
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


class _LoopbackHTTPSServer:
    """Minimal HTTPS loopback server with configurable status code."""

    def __init__(self, cert: Path, key: Path, *, status_code: int = 200):
        self.status_code = status_code
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
                self.sni_seen.append(getattr(tls, "_test_sni", None))
                tls.settimeout(0.5)
                try:
                    data = tls.recv(2048)
                except OSError:
                    return
                if data:
                    body = b"ok\n"
                    hdr = (
                        f"HTTP/1.1 {self.status_code} OK\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                    tls.sendall(hdr + body)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


class DE89VPNSNISelfrouteTests(unittest.TestCase):
    def test_shell_syntax_self_test_and_systemd_unit(self) -> None:
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        res = subprocess.run(["bash", str(SCRIPT), "--self-test"], capture_output=True, text=True, check=True)
        self.assertIn("VPN_SNI_SELFROUTE_SELFTEST=PASS", res.stdout)

        for directive in (
            "DynamicUser=yes",
            "RuntimeDirectory=mnebydns-vpn-sni-selfroute",
            "ExecStartPre=/usr/sbin/nginx -t -c /etc/mnebydns/vpn-sni-selfroute/nginx.conf",
            'ExecStart=/usr/sbin/nginx -c /etc/mnebydns/vpn-sni-selfroute/nginx.conf -g "daemon off;"',
            "ExecStartPost=+/opt/mnebydns-vpn-sni-selfroute-20261127/manage.sh ensure-rule",
            "ExecStopPost=+/opt/mnebydns-vpn-sni-selfroute-20261127/manage.sh rollback-rule",
            "MemoryMax=128M",
            "LimitNOFILE=4096",
            "WantedBy=multi-user.target",
        ):
            self.assertIn(directive, SERVICE_TEXT)

        # Verify unit parses cleanly with systemd-analyze when available.
        sa = subprocess.run(
            ["systemd-analyze", "verify", str(UNIT)],
            capture_output=True,
            text=True,
        )
        self.assertNotIn("Failed to parse", sa.stderr)
        self.assertNotIn("Unknown key", sa.stderr)

    def test_non_root_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (td / "id").write_text("#!/bin/sh\necho 1000\n", encoding="utf-8")
            (td / "id").chmod(0o755)
            env = dict(os.environ, PATH=f"{td}{os.pathsep}{os.environ['PATH']}")
            for cmd in ("stage", "apply", "ensure-rule", "rollback", "rollback-rule", "finalize", "status"):
                res = subprocess.run(["bash", str(SCRIPT), cmd], env=env, capture_output=True, text=True)
                self.assertEqual(res.returncode, 2, f"{cmd} must require root")

    def _setup_env(self, td: Path, *, ru_status_code: int = 200):
        cert, key = _make_cert(td)
        ru_server = _LoopbackHTTPSServer(cert, key, status_code=ru_status_code)
        local_server = _LoopbackHTTPSServer(cert, key, status_code=200)

        root = td / "var/lib/mnebydns-vpn-sni-selfroute-20261127"
        app_dir = td / "opt/mnebydns-vpn-sni-selfroute-20261127"
        conf_dir = td / "etc/mnebydns/vpn-sni-selfroute"
        systemd_dir = td / "etc/systemd/system"
        systemd_dir.mkdir(parents=True)

        rules_file = td / "nat_output.rules"
        svc_active = td / "svc.active"
        svc_enabled = td / "svc.enabled"
        listener_up = td / "listener.up"
        timer_active = td / "timer.active"
        cmd_log = td / "cmd.log"
        probe_log = td / "probe.log"

        bin_dir = td / "bin"
        bin_dir.mkdir()

        ipt = bin_dir / "iptables"
        ipt.write_text(
            f"""#!/usr/bin/env python3
import pathlib, sys
rules_path = pathlib.Path({str(rules_file)!r})
args = sys.argv[1:]
pathlib.Path({str(cmd_log)!r}).open("a").write("iptables " + " ".join(args) + "\\n")
if "-t" in args and "nat" in args:
    idx = args.index("nat")
    op, chain = args[idx + 1], args[idx + 2]
    if chain == "OUTPUT":
        spec = args[idx + 3:]
        if op == "-I" and spec and spec[0].isdigit():
            spec = spec[1:]
        line = " ".join(spec)
        existing = rules_path.read_text().splitlines() if rules_path.exists() else []
        if op == "-C":
            sys.exit(0 if line in existing else 1)
        if op == "-I":
            existing.insert(0, line)
            rules_path.write_text("\\n".join(existing) + ("\\n" if existing else ""))
            sys.exit(0)
        if op == "-D":
            if line not in existing:
                sys.exit(1)
            existing.remove(line)
            rules_path.write_text("\\n".join(existing) + ("\\n" if existing else ""))
            sys.exit(0)
sys.exit(1)
""",
            encoding="utf-8",
        )
        nginx = bin_dir / "nginx"
        nginx.write_text(
            f"""#!/bin/sh
echo "nginx $*" >> "{cmd_log}"
if [ "$1" = "-t" ] && [ "$2" = "-c" ]; then
  grep -Fq "# load_module /usr/lib/nginx/modules/ngx_stream_module.so;" "$3" || exit 1
  if grep -Eq "^[[:space:]]*load_module[[:space:]]" "$3"; then
    echo "DE89 static stream must not use active load_module" >&2
    exit 1
  fi
fi
exit 0
""",
            encoding="utf-8",
        )
        (bin_dir / "id").write_text(
            '#!/bin/sh\n[ "$1" = "-u" ] && [ "$2" = "mnebyvpn-xray" ] && echo 992 && exit 0\n'
            '[ "$1" = "-u" ] && echo 0 && exit 0\nexit 1\n',
            encoding="utf-8",
        )
        (bin_dir / "ss").write_text(
            f"""#!/bin/sh
case "$*" in
  *":443"*) echo 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=10,fd=5))' ;;
  *":18443"*)
    if [ -f "{listener_up}" ]; then
      echo 'LISTEN 0 511 127.0.0.1:18443 0.0.0.0:* users:(("nginx",pid=22,fd=6))'
    fi
    ;;
esac
exit 0
""",
            encoding="utf-8",
        )
        (bin_dir / "systemd-run").write_text(
            f'#!/bin/sh\necho "systemd-run $*" >> "{cmd_log}"\ntouch "{timer_active}"\nexit 0\n',
            encoding="utf-8",
        )
        manage_path = app_dir / "manage.sh"
        (bin_dir / "systemctl").write_text(
            f"""#!/usr/bin/env python3
import os, pathlib, subprocess, sys
args = sys.argv[1:]
pathlib.Path({str(cmd_log)!r}).open("a").write("systemctl " + " ".join(args) + "\\n")
svc_active = pathlib.Path({str(svc_active)!r})
svc_enabled = pathlib.Path({str(svc_enabled)!r})
listener_up = pathlib.Path({str(listener_up)!r})
timer_active = pathlib.Path({str(timer_active)!r})
manage = pathlib.Path({str(manage_path)!r})

if args[0] == "is-active":
    unit = args[-1]
    quiet = "--quiet" in args
    if unit in ("nginx.service", "mnebydns-googlepilot.service", "mnebyvpn-vpn-provisioner.service"):
        if not quiet:
            print("active")
        sys.exit(0)
    if unit.endswith(".timer"):
        ok = timer_active.exists()
    else:
        ok = svc_active.exists()
    if not quiet:
        print("active" if ok else "inactive")
    sys.exit(0 if ok else 1)
if args[0] == "is-enabled":
    quiet = "--quiet" in args
    ok = svc_enabled.exists()
    if not quiet:
        print("enabled" if ok else "disabled")
    sys.exit(0 if ok else 1)
if args[0] == "stop":
    if args[-1].endswith(".timer"):
        timer_active.unlink(missing_ok=True)
    else:
        svc_active.unlink(missing_ok=True)
        listener_up.unlink(missing_ok=True)
        if manage.exists():
            subprocess.run(["bash", str(manage), "rollback-rule"], check=False)
    sys.exit(0)
if args[0] == "enable":
    svc_enabled.touch()
    if "--now" in args:
        svc_active.touch()
        listener_up.touch()
        if manage.exists():
            rc = subprocess.run(["bash", str(manage), "ensure-rule"]).returncode
            sys.exit(rc)
    sys.exit(0)
if args[0] == "disable":
    svc_enabled.unlink(missing_ok=True)
    if "--now" in args:
        svc_active.unlink(missing_ok=True)
        listener_up.unlink(missing_ok=True)
        if manage.exists():
            subprocess.run(["bash", str(manage), "rollback-rule"], check=False)
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        # runuser routes mnebyvpn.site -> ru_server, www.youtube.com -> local_server if NAT active else fail
        (bin_dir / "runuser").write_text(
            f"""#!/usr/bin/env python3
import pathlib, subprocess, sys
sep = sys.argv.index("--")
cmd = sys.argv[sep + 1:]
addr, port, host, mode = cmd[2], cmd[3], cmd[4], cmd[5]
pathlib.Path({str(probe_log)!r}).open("a").write(f"{{addr}}:{{port}}:{{host}}:{{mode}}\\n")
rules = pathlib.Path({str(rules_file)!r}).read_text() if pathlib.Path({str(rules_file)!r}).exists() else ""
nat_active = "-d 188.120.254.223/32 --dport 443" in rules
if host in ("mnebyvpn.site", "www.mnebyvpn.site", "bandbook.site", "www.bandbook.site", "flight-profile.bandbook.site"):
    target_port = {ru_server.port}
elif nat_active:
    target_port = {local_server.port}
else:
    sys.stderr.write("hairpin without NAT\\n")
    sys.exit(1)
res = subprocess.run([sys.executable, "-", "127.0.0.1", str(target_port), host, mode], stdin=sys.stdin)
sys.exit(res.returncode)
""",
            encoding="utf-8",
        )
        for p in bin_dir.iterdir():
            p.chmod(0o755)

        env = dict(os.environ)
        env.update({
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "SSL_CERT_FILE": str(cert),
            "MNEBYDNS_SNI_SELFROUTE_ROOT": str(root),
            "MNEBYDNS_SNI_SELFROUTE_APP_DIR": str(app_dir),
            "MNEBYDNS_SNI_SELFROUTE_SCRIPT": str(manage_path),
            "MNEBYDNS_SNI_SELFROUTE_CONF_DIR": str(conf_dir),
            "MNEBYDNS_SNI_SELFROUTE_PID_FILE": str(td / "run/nginx.pid"),
            "MNEBYDNS_SNI_SELFROUTE_SYSTEMD_DIR": str(systemd_dir),
            "MNEBYDNS_SNI_SELFROUTE_UNIT_SRC": str(UNIT),
            "MNEBYDNS_SNI_SELFROUTE_IPTABLES_BIN": str(ipt),
            "MNEBYDNS_SNI_SELFROUTE_NGINX_BIN": str(nginx),
            "MNEBYDNS_SNI_SELFROUTE_LISTEN_WAIT_TRIES": "4",
            "MNEBYDNS_SNI_SELFROUTE_LISTEN_WAIT_SLEEP": "0.05",
        })
        return env, root, app_dir, conf_dir, systemd_dir, rules_file, timer_active, cmd_log, probe_log, ru_server, local_server

    def test_stage_apply_status_finalize_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, root, app_dir, conf_dir, systemd_dir, rules_file, timer_active, cmd_log, probe_log, ru_srv, loc_srv = (
                self._setup_env(td)
            )
            try:
                p_stage = subprocess.run(["bash", str(SCRIPT), "stage"], env=env, capture_output=True, text=True)
                self.assertEqual(p_stage.returncode, 0, p_stage.stderr)
                self.assertIn("VPN_SNI_SELFROUTE_STAGED=PASS", p_stage.stdout)

                conf_file = conf_dir / "nginx.conf"
                self.assertEqual(stat.S_IMODE(conf_dir.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(conf_file.stat().st_mode), 0o644)
                conf_text = conf_file.read_text(encoding="utf-8")
                self.assertIn("# load_module /usr/lib/nginx/modules/ngx_stream_module.so;", conf_text)
                self.assertIn("worker_connections 2048;", conf_text)
                self.assertIn("listen 127.0.0.1:18443;", conf_text)
                self.assertIn("default 127.0.0.1:443;", conf_text)
                for ru_host in (
                    "mnebyvpn.site",
                    "www.mnebyvpn.site",
                    "bandbook.site",
                    "www.bandbook.site",
                    "flight-profile.bandbook.site",
                ):
                    self.assertIn(f"{ru_host} 188.120.254.223:443;", conf_text)

                p_apply = subprocess.run(["bash", str(SCRIPT), "apply"], env=env, capture_output=True, text=True)
                self.assertEqual(p_apply.returncode, 0, p_apply.stderr)
                self.assertIn("VPN_SNI_SELFROUTE_AUTO_ROLLBACK=ARMED_4M", p_apply.stdout)
                self.assertIn("VPN_SNI_SELFROUTE_APPLIED=PENDING_FINALIZE", p_apply.stdout)
                self.assertTrue(timer_active.exists(), "4m auto-revert timer must remain active until finalize")
                self.assertTrue((root / "installed").is_file())
                self.assertTrue((systemd_dir / "mnebydns-vpn-sni-selfroute-20261127.service").is_file())

                expected_rule = "-p tcp -d 188.120.254.223/32 --dport 443 -m owner --uid-owner 992 -j REDIRECT --to-ports 18443"
                self.assertEqual(rules_file.read_text(encoding="utf-8").splitlines(), [expected_rule])

                logs = cmd_log.read_text(encoding="utf-8").splitlines()
                idx_timer = next(i for i, l in enumerate(logs) if l.startswith("systemd-run "))
                idx_enable = next(i for i, l in enumerate(logs) if "systemctl enable --now" in l)
                idx_ipt_insert = next(i for i, l in enumerate(logs) if "iptables " in l and " -I " in l)
                self.assertLess(idx_timer, idx_enable)
                self.assertLess(idx_timer, idx_ipt_insert)

                probes = probe_log.read_text(encoding="utf-8").splitlines()
                self.assertIn("188.120.254.223:443:mnebyvpn.site:http200", probes)
                self.assertIn("188.120.254.223:443:www.youtube.com:tls", probes)

                p_status = subprocess.run(["bash", str(SCRIPT), "status"], env=env, capture_output=True, text=True)
                self.assertEqual(p_status.returncode, 0, p_status.stderr)
                self.assertIn("VPN_SNI_SELFROUTE_SERVICE=active", p_status.stdout)
                self.assertIn("VPN_SNI_SELFROUTE_RULE=ACTIVE", p_status.stdout)

                p_fin = subprocess.run(["bash", str(SCRIPT), "finalize"], env=env, capture_output=True, text=True)
                self.assertEqual(p_fin.returncode, 0, p_fin.stderr)
                self.assertIn("VPN_SNI_SELFROUTE_FINALIZED=PASS", p_fin.stdout)
                self.assertFalse(timer_active.exists())
                self.assertTrue((root / "confirmed").is_file())

                # Verify rollback-rule preserves $MARK while removing rule, and rollback cleans everything.
                p_rr = subprocess.run(["bash", str(SCRIPT), "rollback-rule"], env=env, capture_output=True, text=True)
                self.assertEqual(p_rr.returncode, 0, p_rr.stderr)
                self.assertEqual(rules_file.read_text(encoding="utf-8").strip(), "")
                self.assertTrue((root / "installed").is_file())

                p_rb = subprocess.run(["bash", str(SCRIPT), "rollback"], env=env, capture_output=True, text=True)
                self.assertEqual(p_rb.returncode, 0, p_rb.stderr)
                self.assertIn("VPN_SNI_SELFROUTE_ROLLBACK=COMPLETE", p_rb.stdout)
                self.assertFalse((root / "installed").exists())
                self.assertFalse((systemd_dir / "mnebydns-vpn-sni-selfroute-20261127.service").exists())
            finally:
                ru_srv.close()
                loc_srv.close()

    def test_apply_auto_reverts_if_post_probe_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, root, _app_dir, _conf_dir, systemd_dir, rules_file, timer_active, _cl, _pl, ru_srv, loc_srv = (
                self._setup_env(td, ru_status_code=200)
            )
            try:
                subprocess.run(["bash", str(SCRIPT), "stage"], env=env, check=True, capture_output=True)
                # Flip RU server to 502 after stage, or force failure via SMARTDNS_HOST missing SAN -> cert error!
                bad_env = dict(env, MNEBYDNS_SNI_SELFROUTE_SMARTDNS_HOST="untrusted.invalid")
                p_apply = subprocess.run(["bash", str(SCRIPT), "apply"], env=bad_env, capture_output=True, text=True)
                self.assertNotEqual(p_apply.returncode, 0)
                self.assertEqual(rules_file.read_text(encoding="utf-8").strip(), "")
                self.assertFalse((root / "installed").exists())
                self.assertFalse(timer_active.exists())
                self.assertFalse((systemd_dir / "mnebydns-vpn-sni-selfroute-20261127.service").exists())
            finally:
                ru_srv.close()
                loc_srv.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
