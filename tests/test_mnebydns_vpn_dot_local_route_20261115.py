#!/usr/bin/env python3
"""Offline regression and executable Bash CLI checks; never touches a VPS."""
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
SCRIPT = ROOT / "scripts/mnebydns-vpn-dot-local-route-20261115.sh"
UNIT = ROOT / "ops/mnebydns-vpn-dot-selfroute-20261115.service"
SOURCE = SCRIPT.read_text(encoding="utf-8")
SERVICE = UNIT.read_text(encoding="utf-8")

PERSONAL_NGINX_CONF = """# DE89 personal-sni sample
stream {
  map $ssl_preread_server_name $personal_dot_target {
    "~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.2:8858;
    default 89.125.90.101:853;
  }
  server {
    listen 0.0.0.0:8854;
    ssl_preread on;
    proxy_pass $personal_dot_target;
  }
}
"""


def _make_cert(tmpdir: Path, *, wildcard: bool = True) -> Path:
    cert = tmpdir / ("cert_wc.pem" if wildcard else "cert_legacy.pem")
    key = tmpdir / ("key_wc.pem" if wildcard else "key_legacy.pem")
    ext = tmpdir / ("ext_wc.cnf" if wildcard else "ext_legacy.cnf")
    san = "DNS:dns.mnebyvpn.site,DNS:*.dns.mnebyvpn.site" if wildcard else "DNS:dns.mnebyvpn.site"
    ext.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=dns.mnebyvpn.site\n"
        f"[v3]\nsubjectAltName={san}\n",
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


class _LoopbackTLSServer:
    def __init__(self, cert: Path, key: Path):
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
                pass

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


def _write_stateful_iptables(bin_dir: Path, rules_file: Path) -> Path:
    ipt = bin_dir / "iptables"
    ipt.write_text(
        f"""#!/usr/bin/env python3
import pathlib, sys
rules_path = pathlib.Path({str(rules_file)!r})
args = sys.argv[1:]
if "-t" in args and "nat" in args:
    idx = args.index("nat")
    op = args[idx + 1]
    chain = args[idx + 2]
    if chain == "PREROUTING" and op == "-C":
        sys.exit(0)
    if chain == "OUTPUT":
        # Strip optional leading insert position "1"
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
    ipt.chmod(0o755)
    return ipt


class VPNLocalDNSRoute(unittest.TestCase):
    def test_shell_syntax(self) -> None:
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_bash_expansions_are_not_escaped(self) -> None:
        self.assertNotIn("\\${", SOURCE, "Literal escaped Bash expansion breaks dispatch and NAT")
        self.assertIn('MODE="${1:-status}"', SOURCE)
        self.assertIn('"${RULE[@]}"', SOURCE)

    def test_exact_vpn_uid_and_both_endpoints(self) -> None:
        self.assertIn("OWNER=mnebyvpn-xray", SOURCE)
        self.assertIn('uid="$(id -u "$OWNER")"', SOURCE)
        self.assertIn('test "$uid" -gt 0', SOURCE)
        self.assertIn('-d "$IP"/32 --dport 853 -m owner --uid-owner "$uid"', SOURCE)
        self.assertIn("ROUTER_PORT=8854", SOURCE)
        self.assertIn("89.125.90.101", SOURCE)
        self.assertIn("188.120.254.223", SOURCE)

    def test_preflight_requires_precise_tls_certificate_mismatch(self) -> None:
        self.assertIn("except ssl.SSLCertVerificationError:", SOURCE)
        self.assertIn('tcp_probe "$DE_IP" "$DOT_PORT" aaaaaaaaaaaa.dns.mnebyvpn.site mismatch', SOURCE)
        self.assertIn('tcp_probe "$DE_IP" "$DOT_PORT" dns.mnebyvpn.site valid', SOURCE)
        self.assertIn('tcp_probe 127.0.0.1 "$ROUTER_PORT" aaaaaaaaaaaa.dns.mnebyvpn.site valid', SOURCE)

    def test_personal_and_legacy_dns_configuration_is_guarded(self) -> None:
        for s in (
            "default 89.125.90.101:853;",
            "10.66.77.2:8858;",
            "10.66.77.2:8856;",
            "listen 0.0.0.0:8854;",
            "mnebydns-dot.service",
            "mnebyvpn-vpn-provisioner.service",
        ):
            self.assertIn(s, SOURCE)

    def test_independent_rollback_rule_and_persistence(self) -> None:
        for s in (
            "--on-active=4m",
            'systemctl is-active --quiet "$TIMER"',
            'iptables -w -t nat -D OUTPUT "${RULE[@]}"',
            'iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"',
            "trap 'rollback' ERR",
            'systemctl enable --now "$SERVICE"',
            'systemctl stop "$TIMER"',
        ):
            self.assertIn(s, SOURCE)
        for s in (
            "Type=oneshot",
            "RemainAfterExit=yes",
            "/manage.sh ensure",
            "/manage.sh rollback-rule",
            "mneby-awg-tg-relay.service",
            "WantedBy=multi-user.target",
        ):
            self.assertIn(s, SERVICE)

    def test_cannot_restart_critical_services(self) -> None:
        for s in (
            "systemctl restart",
            "wg set",
            "wg-quick down",
            "xray-canary.json",
            "Corefile",
            "iptables -F",
            "iptables -X",
            "ip6tables",
            "--dport 443",
            "--dport 2053",
            "iptables -t nat -F",
        ):
            self.assertNotIn(s, SOURCE)

    def test_real_status_bash_argv_with_mock_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            cap = td / "args.txt"
            commands = {
                "id": '#!/bin/sh\n[ "$1" = "-u" ] || exit 3\n[ "$2" = "mnebyvpn-xray" ] || exit 4\necho 1997\n',
                "iptables": '#!/bin/sh\nprintf "%s\\n" "$@" >> "$IPTABLES_CAPTURE"\nexit 1\n',
                "systemctl": "#!/bin/sh\nexit 1\n",
            }
            for name, body in commands.items():
                p = td / name
                p.write_text(body, encoding="utf-8")
                p.chmod(0o755)
            env = dict(os.environ)
            env.update(
                PATH=str(td) + os.pathsep + env["PATH"],
                IPTABLES_CAPTURE=str(cap),
                MNEBYDNS_DOT_SELFROUTE_ROOT=str(td / "state"),
            )
            p = subprocess.run(["bash", str(SCRIPT), "status"], env=env, capture_output=True, text=True, timeout=6)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("VPN_DOT_SELFROUTE_RULE=ABSENT", p.stdout)
            self.assertIn("VPN_DOT_SELFROUTE_RULE_DE=ABSENT", p.stdout)
            self.assertIn("VPN_DOT_SELFROUTE_RULE_RU=ABSENT", p.stdout)
            lines = cap.read_text(encoding="utf-8").splitlines()
            expected = [
                "-w", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-d", "89.125.90.101/32",
                "--dport", "853", "-m", "owner", "--uid-owner", "1997", "-j", "REDIRECT", "--to-ports", "8854",
                "-w", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", "-d", "188.120.254.223/32",
                "--dport", "853", "-m", "owner", "--uid-owner", "1997", "-j", "REDIRECT", "--to-ports", "8854",
            ]
            self.assertEqual(lines, expected)

    def test_invalid_mode_never_runs_admin_commands(self) -> None:
        p = subprocess.run(["bash", str(SCRIPT), "invalid-mode"], capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage:", p.stderr)

    def test_rollback_rule_preserves_mark_while_rollback_clears_it_for_both_ips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            state = td / "state"
            state.mkdir()
            mark = state / "installed"
            mark.write_text("", encoding="utf-8")
            rules_file = td / "nat_output.rules"
            r_de = "-p tcp -d 89.125.90.101/32 --dport 853 -m owner --uid-owner 992 -j REDIRECT --to-ports 8854"
            r_ru = "-p tcp -d 188.120.254.223/32 --dport 853 -m owner --uid-owner 992 -j REDIRECT --to-ports 8854"
            rules_file.write_text(f"{r_de}\n{r_ru}\n", encoding="utf-8")

            bin_dir = td / "bin"
            bin_dir.mkdir()
            _write_stateful_iptables(bin_dir, rules_file)
            (bin_dir / "id").write_text('#!/bin/sh\n[ "$1" = "-u" ] && [ "$2" = "mnebyvpn-xray" ] && echo 992\n', encoding="utf-8")
            (bin_dir / "id").chmod(0o755)
            (bin_dir / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (bin_dir / "systemctl").chmod(0o755)

            env = dict(os.environ)
            env.update(PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", MNEBYDNS_DOT_SELFROUTE_ROOT=str(state))

            p1 = subprocess.run(["bash", str(SCRIPT), "rollback-rule"], env=env, capture_output=True, text=True, timeout=6)
            self.assertEqual(p1.returncode, 0, p1.stderr)
            self.assertIn("VPN_DOT_SELFROUTE_RULE_REMOVED=YES", p1.stdout)
            self.assertEqual(rules_file.read_text(encoding="utf-8").strip(), "")
            self.assertTrue(mark.exists(), "rollback-rule on shutdown/reboot must keep ownership marker")

            rules_file.write_text(f"{r_de}\n{r_ru}\n", encoding="utf-8")
            p2 = subprocess.run(["bash", str(SCRIPT), "rollback"], env=env, capture_output=True, text=True, timeout=6)
            self.assertEqual(p2.returncode, 0, p2.stderr)
            self.assertIn("VPN_DOT_SELFROUTE_ROLLBACK=COMPLETE", p2.stdout)
            self.assertEqual(rules_file.read_text(encoding="utf-8").strip(), "")
            self.assertFalse(mark.exists(), "explicit rollback must remove ownership marker")

    def _setup_upgrade_or_apply_env(self, td: Path, *, legacy_only_before_nat: bool = False):
        cert = _make_cert(td, wildcard=True)
        key = td / "key_wc.pem"
        srv_valid = _LoopbackTLSServer(cert, key)
        srv_legacy = None
        ca_bundle = td / "ca_bundle.pem"
        bundle_text = cert.read_text(encoding="utf-8")
        if legacy_only_before_nat:
            cert_leg = _make_cert(td, wildcard=False)
            srv_legacy = _LoopbackTLSServer(cert_leg, td / "key_legacy.pem")
            bundle_text += cert_leg.read_text(encoding="utf-8")
        ca_bundle.write_text(bundle_text, encoding="utf-8")

        state = td / "var/lib/mnebydns-vpn-dot-selfroute-20261115"
        opt_dir = td / "opt/mnebydns-vpn-dot-selfroute-20261115"
        etc_sni = td / "etc/mnebydns/personal-sni"
        systemd_dir = td / "etc/systemd/system"
        for d in (state, opt_dir, etc_sni, systemd_dir):
            d.mkdir(parents=True)

        conf = etc_sni / "nginx.conf"
        conf.write_text(PERSONAL_NGINX_CONF, encoding="utf-8")
        unit_dst = systemd_dir / "mnebydns-vpn-dot-selfroute-20261115.service"
        unit_dst.write_text(SERVICE, encoding="utf-8")

        manage_dst = opt_dir / "manage.sh"
        rules_file = td / "nat_output.rules"
        probe_log = td / "probes.log"

        bin_dir = td / "bin"
        bin_dir.mkdir()
        ipt = _write_stateful_iptables(bin_dir, rules_file)
        (bin_dir / "id").write_text('#!/bin/sh\n[ "$1" = "-u" ] && [ "$2" = "mnebyvpn-xray" ] && echo 992\n', encoding="utf-8")
        (bin_dir / "ss").write_text("#!/bin/sh\necho 'LISTEN 0 511 0.0.0.0:8854 0.0.0.0:* users:((\"nginx\",pid=10,fd=5))'\n", encoding="utf-8")
        timer_flag = td / "timer.active"
        (bin_dir / "systemd-run").write_text(f"#!/bin/sh\ntouch {str(timer_flag)!r}\nexit 0\n", encoding="utf-8")
        (bin_dir / "systemctl").write_text(
            f'#!/bin/sh\n'
            f'if [ "$1" = "is-active" ]; then\n'
            f'  case "$*" in *.timer*) [ -f "{timer_flag}" ]; exit $? ;; *) exit 0 ;; esac\n'
            f'fi\n'
            f'if [ "$1" = "stop" ]; then rm -f "{timer_flag}"; exit 0; fi\n'
            f'exit 0\n',
            encoding="utf-8",
        )
        # runuser mock routes 89/188:853 -> loopback TLS server (or legacy cert server when NAT rule absent)
        legacy_port = srv_legacy.port if srv_legacy else srv_valid.port
        (bin_dir / "runuser").write_text(
            f"""#!/usr/bin/env python3
import os, pathlib, subprocess, sys
# Expected: runuser -u mnebyvpn-xray -- python3 - ip port host mode
sep = sys.argv.index("--")
cmd = sys.argv[sep + 1:]
ip, port, host, mode = cmd[2], cmd[3], cmd[4], cmd[5]
pathlib.Path({str(probe_log)!r}).open("a").write(f"{{ip}}:{{port}}:{{host}}:{{mode}}\\n")
rules = pathlib.Path({str(rules_file)!r}).read_text() if pathlib.Path({str(rules_file)!r}).exists() else ""
has_ip_nat = f"-d {{ip}}/32 --dport 853" in rules
if ip == "127.0.0.1" and port == "8854":
    target_port = {srv_valid.port}
elif has_ip_nat:
    target_port = {srv_valid.port}
else:
    target_port = {legacy_port}
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
            "SSL_CERT_FILE": str(ca_bundle),
            "MNEBYDNS_DOT_SELFROUTE_ROOT": str(state),
            "MNEBYDNS_DOT_SELFROUTE_CONF": str(conf),
            "MNEBYDNS_DOT_SELFROUTE_SYSTEMD_DIR": str(systemd_dir),
            "MNEBYDNS_DOT_SELFROUTE_IPTABLES_BIN": str(ipt),
            "MNEBYDNS_DOT_SELFROUTE_SCRIPT": str(manage_dst),
        })
        return env, state, manage_dst, rules_file, probe_log, timer_flag, srv_valid, srv_legacy

    def test_ensure_live_upgrade_with_existing_mark_and_89_rule(self) -> None:
        """Critical DE89 live idempotency: existing $MARK + 89 rule upgrades to 89+188 cleanly."""
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, state, manage_dst, rules_file, probe_log, _tf, srv_valid, _ = self._setup_upgrade_or_apply_env(td)
            try:
                # Pre-existing DE89 live state: $MARK exists, old manage.sh exists, 89 rule exists, 188 absent.
                (state / "installed").write_text("", encoding="utf-8")
                manage_dst.write_text("#!/bin/sh\necho OLD_MANAGE_SH\n", encoding="utf-8")
                manage_dst.chmod(0o700)
                r_de = "-p tcp -d 89.125.90.101/32 --dport 853 -m owner --uid-owner 992 -j REDIRECT --to-ports 8854"
                rules_file.write_text(r_de + "\n", encoding="utf-8")

                # First ensure call from new script updates manage.sh, adds 188 without duplicating 89, probes both!
                p1 = subprocess.run(["bash", str(SCRIPT), "ensure"], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(p1.returncode, 0, p1.stderr)
                self.assertIn("VPN_DOT_SELFROUTE_SCRIPT_UPDATED=", p1.stdout)
                self.assertIn("VPN_DOT_SELFROUTE_ACTIVE=CONFIRMED", p1.stdout)
                self.assertEqual(manage_dst.read_text(encoding="utf-8"), SOURCE)
                self.assertEqual(stat.S_IMODE(manage_dst.stat().st_mode), 0o700)

                rules = rules_file.read_text(encoding="utf-8").splitlines()
                r_ru = "-p tcp -d 188.120.254.223/32 --dport 853 -m owner --uid-owner 992 -j REDIRECT --to-ports 8854"
                self.assertEqual(rules.count(r_de), 1, "Must NOT duplicate existing 89.125.90.101 rule")
                self.assertEqual(rules.count(r_ru), 1, "Must add missing 188.120.254.223 rule")

                probes = probe_log.read_text(encoding="utf-8").splitlines()
                self.assertIn("89.125.90.101:853:aaaaaaaaaaaa.dns.mnebyvpn.site:valid", probes)
                self.assertIn("89.125.90.101:853:dns.mnebyvpn.site:valid", probes)
                self.assertIn("188.120.254.223:853:aaaaaaaaaaaa.dns.mnebyvpn.site:valid", probes)
                self.assertIn("188.120.254.223:853:dns.mnebyvpn.site:valid", probes)

                # Second ensure call (from manage_dst itself) is completely idempotent!
                probe_log.write_text("", encoding="utf-8")
                p2 = subprocess.run(["bash", str(manage_dst), "ensure"], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(p2.returncode, 0, p2.stderr)
                self.assertNotIn("SCRIPT_UPDATED", p2.stdout)
                rules2 = rules_file.read_text(encoding="utf-8").splitlines()
                self.assertEqual(rules2.count(r_de), 1)
                self.assertEqual(rules2.count(r_ru), 1)
            finally:
                srv_valid.close()

    def test_ensure_probe_failure_rolls_back_only_newly_inserted_188_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, state, manage_dst, rules_file, _probe_log, _tf, srv_valid, _ = self._setup_upgrade_or_apply_env(td)
            try:
                (state / "installed").write_text("", encoding="utf-8")
                manage_dst.write_text(SOURCE, encoding="utf-8")
                manage_dst.chmod(0o700)
                r_de = "-p tcp -d 89.125.90.101/32 --dport 853 -m owner --uid-owner 992 -j REDIRECT --to-ports 8854"
                rules_file.write_text(r_de + "\n", encoding="utf-8")
                # Force TLS probe failure by pointing SSL_CERT_FILE to non-existent cert!
                bad_env = dict(env, SSL_CERT_FILE=str(td / "missing.pem"))
                p = subprocess.run(["bash", str(SCRIPT), "ensure"], env=bad_env, capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 3)
                self.assertIn("POSTBOOT_CERT_VERIFICATION_FAILED", p.stdout)
                self.assertEqual(rules_file.read_text(encoding="utf-8").splitlines(), [r_de])
            finally:
                srv_valid.close()

    def test_fresh_apply_with_mismatch_preflight_and_both_ips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            env, state, manage_dst, rules_file, probe_log, timer_flag, srv_valid, srv_legacy = (
                self._setup_upgrade_or_apply_env(td, legacy_only_before_nat=True)
            )
            try:
                p = subprocess.run(["bash", str(SCRIPT), "apply"], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("VPN_DOT_SELFROUTE_EXPECTED_CERT_MISMATCH=true", p.stdout)
                self.assertIn("VPN_DOT_SELFROUTE_INSTALLED=PERSISTENT_AND_VERIFIED", p.stdout)
                self.assertTrue((state / "installed").is_file())
                self.assertFalse(timer_flag.exists())
                rules = rules_file.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(rules), 2)
                self.assertIn("89.125.90.101/32", "\n".join(rules))
                self.assertIn("188.120.254.223/32", "\n".join(rules))
                self.assertEqual(manage_dst.read_text(encoding="utf-8"), SOURCE)
            finally:
                srv_valid.close()
                if srv_legacy:
                    srv_legacy.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
