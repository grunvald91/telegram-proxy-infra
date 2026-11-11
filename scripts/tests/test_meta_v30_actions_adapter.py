"""No-VPS, no-credentials regression for v30 SSH workflow adapter."""
from pathlib import Path
import io
import os
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meta_v30_actions_adapter as m

class AdapterTests(unittest.TestCase):
    def test_approval_is_manual_and_validates_peer(self):
        peer="185.137.178.123"
        self.assertEqual(m.check_approval(peer,m.APPROVAL,"workflow_dispatch"),peer)
        for event,approval in (("pull_request",m.APPROVAL),
                               ("push",m.APPROVAL),
                               ("workflow_dispatch",""),
                               ("workflow_dispatch","YES")):
            with self.subTest(event=event,approval=approval):
                with self.assertRaises(PermissionError):
                    m.check_approval(peer,approval,event)
        for ip in ("0.0.0.0","10.0.0.1","127.0.0.1","::1",m.DE,m.RU):
            with self.assertRaises(ValueError):
                m.check_approval(ip,m.APPROVAL,"workflow_dispatch")

    def test_bundle_has_only_flat_explicit_regular_source_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"ops").mkdir();(root/"scripts").mkdir()
            (root/"ops/mnebydns-owner-ssh-known_hosts").write_text("pinned")
            for name in m.FILES:(root/"scripts"/name).write_text(name)
            data=m.bundle(root)
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                names=tar.getnames()
                self.assertEqual(tuple(names),m.FILES)
                self.assertTrue(all(t.isfile() and t.mode==0o600 for t in tar))
            (root/"scripts"/m.FILES[0]).unlink()
            (root/"scripts"/m.FILES[0]).symlink_to(root/"scripts"/m.FILES[1])
            with self.assertRaisesRegex(RuntimeError,"symlink"):
                m.bundle(root)

    def test_ru_staging_creates_missing_libexec_parent_without_overwriting_stage(self):
        remote=object.__new__(m.Remote)
        calls=[]
        remote.call=lambda role,command,**kw: calls.append((role,command,kw))
        remote.payload=b"fixture"
        remote.stage_files("ru")
        self.assertEqual(len(calls),1)
        self.assertIn("test ! -L /usr/local/libexec",calls[0][1])
        self.assertIn("install -d -m 0755 -o root -g root /usr/local/libexec",calls[0][1])
        self.assertIn("test ! -e /usr/local/libexec/mneby-meta-v26",calls[0][1])
        self.assertEqual(calls[0][2]["data"],b"fixture")

    def test_approved_thirty_minute_test(self):
        calls=[]
        class Fake:
            def preflight(self,role):pass
            def stage_files(self,role):pass
            def run(self,role,action,peer=None):pass
            def active_window(self,seconds):calls.append(seconds)
            def reset(self,role):pass
        with patch.object(m,"Remote",return_value=Fake()), \
             patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_dispatch",
                         "MNEBY_META_V30_APPROVED":m.APPROVAL}), \
             patch.object(m.signal,"signal"):
            m.main(["--mode","activate","--phone-ip","185.137.178.123","--minutes","30"])
        self.assertEqual(calls,[1800])

    def test_no_unapproved_remote_command_or_injection(self):
        remote=object.__new__(m.Remote)
        calls=[]
        remote.call=lambda *a,**k: calls.append((a,k)) or "ok"
        with self.assertRaises(ValueError):remote.run("de","flush")
        with self.assertRaises(ValueError):remote.run("ru","enable-dns")
        with self.assertRaises(ValueError):remote.run("de","stage","8.8.8.8; rm -rf /")
        with self.assertRaises(ValueError):remote.run("de","stage")
        with self.assertRaises(ValueError):remote.run("de","rollback","8.8.8.8")
        self.assertEqual(calls,[])
        remote.run("de","stage","8.8.8.8")
        self.assertIn(" --peer 8.8.8.8",calls[0][0][1])

    def test_health_requires_actual_services_routes_and_timers(self):
        remote=object.__new__(m.Remote)
        remote.run=lambda role,action: "\n".join(m.HEALTH[role])+"\n"
        remote.verify_health()
        remote.run=lambda role,action: "\n".join(m.HEALTH[role][:-1])
        with self.assertRaisesRegex(RuntimeError,"timer_active"):
            remote.verify_health()

    def test_activate_both_then_cleanup_in_correct_order(self):
        calls=[]
        class Fake:
            def preflight(self,role):calls.append(("preflight",role))
            def stage_files(self,role):calls.append(("stagefiles",role))
            def run(self,role,action,peer=None):
                calls.append(("run",role,action,peer))
            def active_window(self,seconds):calls.append(("window",seconds))
            def reset(self,role):calls.append(("reset",role))
        with patch.object(m,"Remote",return_value=Fake()), \
             patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_dispatch",
                         "MNEBY_META_V30_APPROVED":m.APPROVAL}):
            m.main(["--mode","activate","--phone-ip","8.8.8.8","--minutes","5"])
        self.assertEqual(calls[:4],[("preflight","de"),("preflight","ru"),
                                    ("stagefiles","de"),("stagefiles","ru")])
        self.assertEqual(calls[-2:],[("reset","ru"),("reset","de")])
        self.assertIn(("run","de","enable-dns",None),calls)
        self.assertIn(("window",300),calls)
        self.assertLess(calls.index(("run","de","disable-dns",None)),
                        calls.index(("run","ru","rollback",None)))

    def test_activation_failure_does_not_skip_staged_server_reset(self):
        calls=[]
        class Fake:
            def preflight(self,role):calls.append(("preflight",role))
            def stage_files(self,role):
                calls.append(("stagefiles",role))
                if role=="ru":raise RuntimeError("unavailable")
            def reset(self,role):calls.append(("reset",role))
        with patch.object(m,"Remote",return_value=Fake()), \
             patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_dispatch",
                         "MNEBY_META_V30_APPROVED":m.APPROVAL}):
            with self.assertRaisesRegex(RuntimeError,"cleanup verified"):
                m.main(["--mode","activate","--phone-ip","8.8.8.8"])
        self.assertIn(("reset","de"),calls)
        self.assertNotIn(("reset","ru"),calls)

    def test_cancel_during_live_window_attempts_ordered_rollback(self):
        calls=[]
        class Fake:
            def preflight(self,role):calls.append(("preflight",role))
            def stage_files(self,role):calls.append(("stagefiles",role))
            def run(self,role,action,peer=None):
                calls.append(("run",role,action,peer))
            def active_window(self,seconds):
                m.cancel_trial(15,None)
            def reset(self,role):calls.append(("reset",role))
        with patch.object(m,"Remote",return_value=Fake()), \
             patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_dispatch",
                         "MNEBY_META_V30_APPROVED":m.APPROVAL}), \
             patch.object(m.signal,"signal"):
            with self.assertRaisesRegex(RuntimeError,"cleanup verified"):
                m.main(["--mode","activate","--phone-ip","8.8.8.8"])
        self.assertEqual(calls[-5:],[("run","de","disable-dns",None),
                                     ("run","ru","rollback",None),
                                     ("run","de","rollback",None),
                                     ("reset","ru"),("reset","de")])

    def test_preflight_has_no_stage_or_restart(self):
        calls=[]
        class Fake:
            def preflight(self,role):calls.append(role)
            def stage_files(self,role):raise AssertionError("mutating")
        with patch.object(m,"Remote",return_value=Fake()):
            m.main(["--mode","preflight"])
        self.assertEqual(calls,["de","ru"])

    def test_live_never_runs_without_approval_even_with_valid_ip(self):
        with patch.object(m,"Remote",side_effect=AssertionError("must not connect")), \
             patch.dict(os.environ,{"GITHUB_EVENT_NAME":"pull_request",
                         "MNEBY_META_V30_APPROVED":m.APPROVAL}):
            with self.assertRaises(PermissionError):
                m.main(["--mode","activate","--phone-ip","8.8.8.8"])
if __name__=="__main__":
    unittest.main()
