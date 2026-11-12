"""Failure-path checks for v26 two-server staging; no VPS/network access."""
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meta_v26_de_stage as de
import meta_v26_ru_stage as ru
import meta_v26_readonly_preflight as preflight

class StagingRollbackTests(unittest.TestCase):
    def test_trial_cleanup_budget_on_both_nodes_is_independent(self):
        self.assertGreater(de.CLEANUP_SECONDS,de.CLIENT_SECONDS+300)
        self.assertGreater(ru.CLEANUP_SECONDS,de.CLIENT_SECONDS+300)
        self.assertGreater(ru.WORKER_SECONDS,ru.CLEANUP_SECONDS)
        self.assertEqual(ru.RU_EDGE,"188.120.254.223")
        self.assertEqual(de.EDGE,"89.125.90.101")

    def test_de_preflight_refuses_to_pass_without_core_runtime_source_split(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            core=root/"Corefile";core.write_text("baseline")
            nginx=root/"nginx.conf";nginx.write_text("baseline")
            with patch.object(preflight.de,"ROOT",root/"absent"), \
                 patch.object(preflight.de,"LIVE_DNS",core), \
                 patch.object(preflight.de,"LIVE_NGINX",nginx), \
                 patch.object(preflight.de,"guards"), \
                 patch.object(preflight.de,"active",return_value=False), \
                 patch.object(preflight.de,"compiled_plugins",return_value="view template tls"), \
                 patch.object(preflight,"render") as renderer, \
                 patch.object(preflight,"verify_core_view_runtime",side_effect=RuntimeError("real view mismatch")) as smoke, \
                 patch.object(preflight,"verify_dot_view_runtime") as dot_smoke:
                with self.assertRaisesRegex(RuntimeError,"real view mismatch"):
                    preflight.audit_de()
                renderer.return_value.verify_rollback.assert_called_once_with()
                smoke.assert_called_once_with()
                dot_smoke.assert_not_called()

    def test_ru_non_meta_fallback_checks_real_tcp_connection(self):
        from unittest.mock import MagicMock
        with patch.object(ru.socket,"create_connection",return_value=MagicMock()) as dial:
            ru.verify_non_meta_fallback()
            dial.assert_called_once_with((ru.RU_EDGE,443),timeout=4)
        with patch.object(ru.socket,"create_connection",side_effect=OSError("refused")):
            with self.assertRaisesRegex(RuntimeError,"fallback is unreachable"):
                ru.verify_non_meta_fallback()

    def test_ru_rejects_unsafe_peer_before_any_command(self):
        for peer in ("0.0.0.0","127.0.0.1","10.66.77.1",
                     "192.168.1.1","188.120.254.223",
                     "89.125.90.101","8.8.8.8/32"):
            with self.subTest(peer=peer),self.assertRaises(ValueError):
                ru.checked_peer(peer)
        self.assertEqual(ru.checked_peer("8.8.8.8"),"8.8.8.8")

    def test_de_rejects_invalid_peer_before_live_service_commands(self):
        with patch.object(de,"flag"),patch.object(de,"cmd",side_effect=AssertionError("mutated")):
            with self.assertRaises(ValueError):
                de.stage("10.0.0.5")

    def test_de_rollback_restores_both_configs_and_verifies_services(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d)
            root=directory/"state";root.mkdir()
            ng=directory/"nginx.conf";dns=directory/"Corefile"
            originals={"nginx":b"original nginx config\n","dns":b"original DNS config\n"}
            trials={"nginx":b"candidate nginx config\n","dns":b"candidate DNS config\n"}
            for key in originals:
                (root/(key+".original")).write_bytes(originals[key])
                (root/(key+".candidate")).write_bytes(trials[key])
            (root/"armed").write_text("armed\n")
            ng.write_bytes(trials["nginx"]);dns.write_bytes(trials["dns"])
            calls=[]
            def fake_cmd(args,**kwargs):
                calls.append(tuple(args))
                return SimpleNamespace(returncode=0,stdout="")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),patch.object(de,"active",return_value=True),\
                 patch.object(de,"cmd",side_effect=fake_cmd):
                de._rollback_locked()
                self.assertEqual(ng.read_bytes(),originals["nginx"])
                self.assertEqual(dns.read_bytes(),originals["dns"])
                self.assertTrue(any(x[:3]==("systemctl","restart","mnebydns-dot.service") for x in calls))
                self.assertTrue(any(x[:3]==("systemctl","reload","nginx.service") for x in calls))
                calls.clear()
                de._rollback_locked()
                self.assertFalse(calls,"already restored must not restart production services")

    def test_de_rollback_attempts_nginx_even_if_dns_restart_fails(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);root=directory/"state";root.mkdir()
            ng=directory/"nginx.conf";dns=directory/"Corefile"
            for key,live in (("nginx",ng),("dns",dns)):
                (root/(key+".original")).write_bytes(b"stable")
                (root/(key+".candidate")).write_bytes(b"candidate")
                live.write_bytes(b"candidate")
            (root/"armed").write_bytes(b"armed")
            calls=[]
            def failing_dns(args,**kwargs):
                calls.append(tuple(args))
                if args==["systemctl","restart","mnebydns-dot.service"]:
                    raise RuntimeError("simulated DNS restart failure")
                return SimpleNamespace(returncode=0,stdout="")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),patch.object(de,"active",return_value=True),\
                 patch.object(de,"cmd",side_effect=failing_dns):
                with self.assertRaisesRegex(RuntimeError,"dns_restart"):
                    de._rollback_locked()
            self.assertEqual(ng.read_bytes(),b"stable")
            self.assertEqual(dns.read_bytes(),b"stable")
            self.assertIn(("systemctl","reload","nginx.service"),calls)
            self.assertIn(("nginx","-t"),calls)

    def test_de_rollback_external_drift_fails_before_writes(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);root=directory/"state";root.mkdir()
            ng=directory/"nginx.conf";dns=directory/"Corefile"
            for key in ("nginx","dns"):
                (root/(key+".original")).write_bytes(b"old")
                (root/(key+".candidate")).write_bytes(b"trial")
            (root/"armed").write_bytes(b"armed")
            ng.write_bytes(b"external changes");dns.write_bytes(b"trial")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),\
                 patch.object(de,"cmd",side_effect=AssertionError("service should not change")):
                with self.assertRaisesRegex(RuntimeError,"external DE nginx"):
                    de._rollback_locked()
            self.assertEqual(ng.read_bytes(),b"external changes")
            self.assertEqual(dns.read_bytes(),b"trial")

    def test_de_reset_only_after_restoration_and_watchdog_disarm(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"state";root.mkdir()
            ng=Path(d)/"nginx";dns=Path(d)/"dns"
            ng.write_bytes(b"original");dns.write_bytes(b"original")
            (root/"armed").write_bytes(b"armed")
            for key in ("nginx","dns"):
                (root/(key+".original")).write_bytes(b"original")
                (root/(key+".candidate")).write_bytes(b"candidate")
            def service(name):return name in ("nginx.service","mnebydns-dot.service")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),patch.object(de,"active",side_effect=service),\
                 patch.object(de,"cmd",side_effect=AssertionError("no service mutation")):
                de.reset()
            self.assertFalse(root.exists())

    def test_de_selective_dns_disable_keeps_nginx_routes_until_ru_teardown(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);root=directory/"state";root.mkdir()
            ng=directory/"nginx.conf";dns=directory/"Corefile"
            for key,live in (("nginx",ng),("dns",dns)):
                (root/(key+".original")).write_bytes(b"baseline")
                (root/(key+".candidate")).write_bytes(b"pilot")
                live.write_bytes(b"pilot")
            (root/"armed").write_bytes(b"armed")
            calls=[]
            def call(args,**kwargs):
                calls.append(tuple(args))
                return SimpleNamespace(returncode=0,stdout="")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),patch.object(de,"flag"),\
                 patch.object(de,"active",return_value=True),\
                 patch.object(de,"cmd",side_effect=call):
                de.disable_dns()
                self.assertEqual(dns.read_bytes(),b"baseline")
                self.assertEqual(ng.read_bytes(),b"pilot")
                de.disable_dns()
            self.assertEqual(calls.count(("systemctl","restart","mnebydns-dot.service")),1)

    def test_de_selective_dns_disable_refuses_drift(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);root=directory/"state";root.mkdir()
            ng=directory/"nginx.conf";dns=directory/"Corefile"
            for key,live in (("nginx",ng),("dns",dns)):
                (root/(key+".original")).write_bytes(b"baseline")
                (root/(key+".candidate")).write_bytes(b"pilot")
                live.write_bytes(b"pilot")
            (root/"armed").write_bytes(b"armed")
            dns.write_bytes(b"external edit")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),patch.object(de,"flag"),\
                 patch.object(de,"cmd",side_effect=AssertionError("no mutation")):
                with self.assertRaisesRegex(RuntimeError,"drift"):
                    de.disable_dns()
            self.assertEqual(dns.read_bytes(),b"external edit")

    def test_de_reset_incomplete_prearm_staging_without_snapshots(self):
        # A failure before 'armed' cannot modify live Nginx/CoreDNS, but
        # previously made reset() demand nonexistent candidate checkpoints.
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"state";root.mkdir()
            ng=Path(d)/"nginx.conf";dns=Path(d)/"Corefile"
            ng.write_bytes(b"baseline nginx");dns.write_bytes(b"baseline dns")
            (root/"nginx.original").write_bytes(ng.read_bytes())
            (root/"lock").touch()
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),\
                 patch.object(de,"active",side_effect=lambda name: name in
                     ("nginx.service","mnebydns-dot.service",de.UNIT+".timer")),\
                 patch.object(de,"cmd") as command:
                # This fake indicates an active watchdog throughout; a real
                # systemctl stop would make it inactive, so model that state.
                timer_running={"value":True}
                def act(service):
                    return (timer_running["value"] if service==de.UNIT+".timer"
                            else service in ("nginx.service","mnebydns-dot.service"))
                def stop(args,**kwargs):
                    if args[:2]==["systemctl","stop"]:timer_running["value"]=False
                    return SimpleNamespace(returncode=0,stdout="")
                with patch.object(de,"active",side_effect=act):
                    command.side_effect=stop
                    de.reset()
                command.assert_called_once()
            self.assertFalse(root.exists())
            self.assertEqual(ng.read_bytes(),b"baseline nginx")
            self.assertEqual(dns.read_bytes(),b"baseline dns")

    def test_de_reset_incomplete_prearm_rejects_live_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"state";root.mkdir()
            ng=Path(d)/"nginx.conf";dns=Path(d)/"Corefile"
            ng.write_bytes(b"external edit");dns.write_bytes(b"baseline dns")
            (root/"nginx.original").write_bytes(b"baseline nginx")
            with patch.object(de,"ROOT",root),patch.object(de,"LIVE_NGINX",ng),\
                 patch.object(de,"LIVE_DNS",dns),\
                 patch.object(de,"active",return_value=True),\
                 patch.object(de,"cmd",side_effect=AssertionError("must not mutate")):
                with self.assertRaisesRegex(RuntimeError,"baseline drift"):
                    de.reset()
            self.assertTrue(root.exists())
            self.assertEqual(ng.read_bytes(),b"external edit")

    def test_ru_reset_requires_worker_and_rules_absent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"state";root.mkdir()
            (root/"armed").write_bytes(b"armed")
            fake=SimpleNamespace(returncode=0,stdout="MainPID=0\nActiveState=inactive\n")
            with patch.object(ru,"ROOT",root),patch.object(ru,"table_exists",return_value=False),\
                 patch.object(ru,"ready_worker",return_value=False),\
                 patch.object(ru,"active",return_value=False),\
                 patch.object(ru,"cmd",return_value=fake):
                ru.reset()
            self.assertFalse(root.exists())

    def test_ru_rollback_removes_redirect_before_stopping_worker(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"armed").write_text("armed\n")
            calls=[]
            state={"present":True}
            def fake_cmd(args,**kwargs):
                calls.append(tuple(args))
                if args[:3]==["nft","delete","table"]:
                    state["present"]=False
                if args[:2]==["systemctl","show"]:
                    return SimpleNamespace(returncode=0,stdout="MainPID=0\nActiveState=inactive\n")
                return SimpleNamespace(returncode=0,stdout="")
            with patch.object(ru,"ROOT",root),patch.object(ru,"table_exists",side_effect=lambda:state["present"]),\
                 patch.object(ru,"cmd",side_effect=fake_cmd):
                ru._rollback_locked()
            self.assertEqual(calls[0][:3],("nft","delete","table"))
            self.assertIn(("systemctl","stop",ru.WORKER+".service"),calls)
            self.assertFalse(state["present"])


    def test_ru_firewall_is_one_phone_exact_18443_and_never_all(self):
        args=ru.firewall_args("185.137.178.123")
        self.assertEqual(args[:4],["-s","185.137.178.123/32","-d",ru.RU_EDGE+"/32"])
        self.assertIn("--dport",args)
        self.assertEqual(args[args.index("--dport")+1],"18443")
        self.assertEqual(args[-2:],["-j","ACCEPT"])
        self.assertEqual(args[args.index("--comment")+1],ru.FIREWALL_COMMENT)
        for unsafe in ("all","0.0.0.0","127.0.0.1","192.168.1.3",
                       "185.137.178.123/0",ru.RU_EDGE):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                ru.firewall_args(unsafe)

    def test_ru_scoped_firewall_install_and_idempotent_remove(self):
        commands=[]
        state={"rule":False}
        def fake_cmd(argv,**kwargs):
            commands.append(tuple(argv))
            if "-C" in argv:
                return SimpleNamespace(returncode=0 if state["rule"] else 1,stdout="")
            if "-I" in argv:
                state["rule"]=True
            elif "-D" in argv:
                state["rule"]=False
            return SimpleNamespace(returncode=0,stdout="")
        peer="185.137.178.123"
        with patch.object(ru,"cmd",side_effect=fake_cmd):
            ru.firewall_install(peer)
            self.assertTrue(state["rule"])
            ru.firewall_remove(peer)
            ru.firewall_remove(peer)
            self.assertFalse(state["rule"])
        mutating=[x for x in commands if "-I" in x or "-D" in x]
        self.assertEqual(len(mutating),2)
        self.assertEqual(mutating[0][:6],("iptables","-w","5","-I",ru.FIREWALL_CHAIN,"1"))
        self.assertEqual(mutating[1][:5],("iptables","-w","5","-D",ru.FIREWALL_CHAIN))
        self.assertTrue(all(ru.FIREWALL_COMMENT in x for x in mutating))

    def test_ru_rollback_removes_ufw_exception_after_nft_and_preserves_marker_on_error(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"armed").write_text("armed")
            (root/"peer").write_text("185.137.178.123")
            marker=root/"firewall-pending";marker.write_text("185.137.178.123")
            nft={"on":True};actions=[];fail={"on":True}
            def command(argv,**kw):
                actions.append(tuple(argv))
                if argv[:3]==["nft","delete","table"]:nft["on"]=False
                if argv[:2]==["systemctl","show"]:
                    return SimpleNamespace(returncode=0,stdout="MainPID=0\\nActiveState=inactive\\n")
                return SimpleNamespace(returncode=0,stdout="")
            def remove(peer):
                actions.append(("remove",peer))
                if fail["on"]:raise RuntimeError("simulated UFW delete failure")
            with patch.object(ru,"ROOT",root),patch.object(ru,"table_exists",side_effect=lambda:nft["on"]),\\
                 patch.object(ru,"cmd",side_effect=command),patch.object(ru,"firewall_remove",side_effect=remove):
                with self.assertRaisesRegex(RuntimeError,"firewall_remove"):
                    ru._rollback_locked()
                self.assertTrue(marker.exists(),"failed cleanup must retain recovery intent")
                self.assertEqual(actions[0][:3],("nft","delete","table"))
                fail["on"]=False
                ru._rollback_locked()
                self.assertFalse(marker.exists())
                self.assertIn(("remove","185.137.178.123"),actions)

    def test_ru_firewall_check_fails_closed_on_iptables_errors(self):
        with patch.object(ru,"cmd",return_value=SimpleNamespace(returncode=4,stdout="")):
            with self.assertRaisesRegex(RuntimeError,"inspect scoped firewall"):
                ru.firewall_present("185.137.178.123")

if __name__=="__main__":unittest.main()
