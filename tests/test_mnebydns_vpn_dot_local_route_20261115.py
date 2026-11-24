#!/usr/bin/env python3
"""Offline regression and executable Bash CLI checks; never touches a VPS."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts/mnebydns-vpn-dot-local-route-20261115.sh"
UNIT=ROOT/"ops/mnebydns-vpn-dot-selfroute-20261115.service"
SOURCE=SCRIPT.read_text()
SERVICE=UNIT.read_text()

class VPNLocalDNSRoute(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash","-n",str(SCRIPT)],check=True)

    def test_bash_expansions_are_not_escaped(self):
        self.assertNotIn("\\${", SOURCE, "Literal escaped Bash expansion breaks dispatch and NAT")
        self.assertIn('MODE="${1:-status}"', SOURCE)
        self.assertIn('"${RULE[@]}"',SOURCE)

    def test_exact_vpn_uid_and_endpoint(self):
        self.assertIn("OWNER=mnebyvpn-xray",SOURCE)
        self.assertIn('uid="$(id -u "$OWNER")"',SOURCE)
        self.assertIn('test "$uid" -gt 0',SOURCE)
        self.assertIn('-d "$IP"/32 --dport 853 -m owner --uid-owner "$uid"',SOURCE)
        self.assertIn('ROUTER_PORT=8854',SOURCE)

    def test_preflight_requires_precise_tls_certificate_mismatch(self):
        self.assertIn("except ssl.SSLCertVerificationError:",SOURCE)
        self.assertIn('tcp_probe "$IP" 853 aaaaaaaaaaaa.dns.mnebyvpn.site mismatch',SOURCE)
        self.assertIn('tcp_probe "$IP" 853 dns.mnebyvpn.site valid',SOURCE)
        self.assertIn('tcp_probe 127.0.0.1 8854 aaaaaaaaaaaa.dns.mnebyvpn.site valid',SOURCE)

    def test_personal_and_legacy_dns_configuration_is_guarded(self):
        for s in ("default 89.125.90.101:853;","10.66.77.2:8858;","10.66.77.2:8856;",
                  "listen 0.0.0.0:8854;","mnebydns-dot.service",
                  "mnebyvpn-vpn-provisioner.service"):
            self.assertIn(s,SOURCE)

    def test_independent_rollback_rule_and_persistence(self):
        for s in ("--on-active=4m",'systemctl is-active --quiet "$TIMER"',
                  'iptables -w -t nat -D OUTPUT "${RULE[@]}"',
                  'iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"',
                  "trap 'rollback' ERR",'systemctl enable --now "$SERVICE"',
                  'systemctl stop "$TIMER"'):
            self.assertIn(s,SOURCE)
        for s in ("Type=oneshot","RemainAfterExit=yes","/manage.sh ensure",
                  "/manage.sh rollback-rule","mneby-awg-tg-relay.service",
                  "WantedBy=multi-user.target"):
            self.assertIn(s,SERVICE)

    def test_cannot_restart_critical_services(self):
        for s in ("systemctl restart","wg set","wg-quick down","xray-canary.json",
                  "Corefile","iptables -F","iptables -X","ip6tables",
                  "--dport 443","--dport 2053","iptables -t nat -F"):
            self.assertNotIn(s,SOURCE)

    def test_real_status_bash_argv_with_mock_commands(self):
        # Executes the actual script and catches accidental escaped-array quoting.
        with tempfile.TemporaryDirectory() as tmp:
            td=Path(tmp)
            cap=td/"args.txt"
            commands={
              "id":'#!/bin/sh\n[ "$1" = "-u" ] || exit 3\n[ "$2" = "mnebyvpn-xray" ] || exit 4\necho 1997\n',
              "iptables":'#!/bin/sh\nprintf "%s\\n" "$@" > "$IPTABLES_CAPTURE"\nexit 1\n',
              "systemctl":'#!/bin/sh\nexit 1\n',
            }
            for name,body in commands.items():
                p=td/name;p.write_text(body);p.chmod(0o755)
            env=dict(os.environ)
            env.update(PATH=str(td)+os.pathsep+env["PATH"],IPTABLES_CAPTURE=str(cap))
            p=subprocess.run(["bash",str(SCRIPT),"status"],env=env,
                             capture_output=True,text=True,timeout=6)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn("VPN_DOT_SELFROUTE_RULE=ABSENT",p.stdout)
            self.assertEqual(cap.read_text().splitlines(),
                ["-w","-t","nat","-C","OUTPUT","-p","tcp","-d","89.125.90.101/32",
                 "--dport","853","-m","owner","--uid-owner","1997",
                 "-j","REDIRECT","--to-ports","8854"])

    def test_invalid_mode_never_runs_admin_commands(self):
        p=subprocess.run(["bash",str(SCRIPT),"invalid-mode"],
                         capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,2)
        self.assertIn("usage:",p.stderr)

    def test_rollback_rule_preserves_mark_while_rollback_clears_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            td=Path(tmp)
            state=td/"state"
            state.mkdir()
            mark=state/"installed"
            mark.write_text("")
            rule_flag=td/"rule_present"
            rule_flag.write_text("1")
            script_copy=td/"manage.sh"
            patched=SOURCE.replace(
                "ROOT=/var/lib/mnebydns-vpn-dot-selfroute-20261115",
                f"ROOT={state}",
                1,
            )
            self.assertNotEqual(patched,SOURCE)
            script_copy.write_text(patched)
            script_copy.chmod(0o755)
            commands={
                "id":'#!/bin/sh\n[ "$1" = "-u" ] || exit 3\n[ "$2" = "mnebyvpn-xray" ] || exit 4\necho 992\n',
                "iptables":(
                    '#!/bin/sh\n'
                    'if [ "$3" = "nat" ] && [ "$4" = "-C" ]; then [ -f "$RULE_FLAG" ]; exit $?; fi\n'
                    'if [ "$3" = "nat" ] && [ "$4" = "-D" ]; then rm -f "$RULE_FLAG"; exit 0; fi\n'
                    'exit 1\n'
                ),
                "systemctl":'#!/bin/sh\nexit 0\n',
            }
            for name,body in commands.items():
                p=td/name;p.write_text(body);p.chmod(0o755)
            env=dict(os.environ)
            env.update(PATH=str(td)+os.pathsep+env["PATH"],RULE_FLAG=str(rule_flag))

            p1=subprocess.run(["bash",str(script_copy),"rollback-rule"],env=env,
                              capture_output=True,text=True,timeout=6)
            self.assertEqual(p1.returncode,0,p1.stderr)
            self.assertIn("VPN_DOT_SELFROUTE_RULE_REMOVED=YES",p1.stdout)
            self.assertFalse(rule_flag.exists())
            self.assertTrue(mark.exists(),"rollback-rule on shutdown/reboot must keep ownership marker")

            rule_flag.write_text("1")
            p2=subprocess.run(["bash",str(script_copy),"rollback"],env=env,
                              capture_output=True,text=True,timeout=6)
            self.assertEqual(p2.returncode,0,p2.stderr)
            self.assertIn("VPN_DOT_SELFROUTE_ROLLBACK=COMPLETE",p2.stdout)
            self.assertFalse(rule_flag.exists())
            self.assertFalse(mark.exists(),"explicit rollback must remove ownership marker")

if __name__=="__main__":
    unittest.main(verbosity=2)
