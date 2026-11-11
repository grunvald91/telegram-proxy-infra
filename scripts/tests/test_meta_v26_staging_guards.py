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
                 patch.object(preflight,"verify_core_view_runtime",side_effect=RuntimeError("real view mismatch")) as smoke:
                with self.assertRaisesRegex(RuntimeError,"real view mismatch"):
                    preflight.audit_de()
                renderer.return_value.verify_rollback.assert_called_once_with()
                smoke.assert_called_once_with()

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

if __name__=="__main__":unittest.main()
