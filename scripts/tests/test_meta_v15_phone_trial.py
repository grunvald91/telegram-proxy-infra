"""Controller failure-path regression; all service/nft calls are synthetic."""
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


class ControllerTests(unittest.TestCase):
    def setUp(self):
        import mnebydns_iglite_route_only_v11 as route
        base_keys=("ROOT","UNIT","TABLE","PERSISTENT_STAGE")
        route_keys=("ROLLBACK_SCRIPT","TRANSPORT_LABEL","MUTATION_GUARD","LIVE_CHECK","TRIAL_WAIT","rollback")
        old_base={key:getattr(route.base,key) for key in base_keys}
        old_route={key:getattr(route,key) for key in route_keys}
        self.trial=importlib.import_module("meta_v15_phone_trial")
        for key,value in old_base.items():setattr(route.base,key,value)
        for key,value in old_route.items():setattr(route,key,value)
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        self.state=Path(td.name);(self.state/"armed").write_bytes(b"yes")
        self.calls=[];self.table=True;self.nft_error=False;self.stuck=False
        self.worker=dict(LoadState="loaded",ActiveState="active",SubState="running",MainPID="123")
        self.listener=f'LISTEN 0 64 {self.trial.EDGE}:{self.trial.PORT} 0.0.0.0:* users:(("python3",pid=123,fd=3))\n'
        for name,value in (("STATE",self.state),("command",self.command)):
            p=patch.object(self.trial,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(self.trial.route,"rollback");self.restore=p.start();self.addCleanup(p.stop)

    def command(self,args,**kwargs):
        self.calls.append(tuple(args))
        if args[0]=="nft":
            if self.nft_error:
                if kwargs.get("check",True):raise RuntimeError("synthetic nft unavailable")
                return SimpleNamespace(returncode=1,stdout="")
            if "delete" in args:self.table=False
            if args[1:]==["-j","list","tables"]:
                tables=[{"table":{"family":"inet","name":self.trial.TABLE}}] if self.table else []
                return SimpleNamespace(returncode=0,stdout=json.dumps({"nftables":tables}))
            return SimpleNamespace(returncode=0 if self.table else 1,stdout="")
        if args[:2]==["systemctl","stop"]:
            if self.stuck:
                self.worker.update(ActiveState="deactivating",SubState="stop-sigterm")
                return SimpleNamespace(returncode=1,stdout="")
            self.worker.update(ActiveState="inactive",SubState="dead",MainPID="0")
        if args[:2]==["systemctl","show"]:
            return SimpleNamespace(returncode=0,stdout="\n".join(key+"="+value for key,value in self.worker.items()))
        if args[:2]==["systemctl","is-active"]:
            return SimpleNamespace(returncode=0 if self.worker["ActiveState"]=="active" else 3,stdout="")
        if args[0]=="ss":return SimpleNamespace(returncode=0,stdout=self.listener)
        return SimpleNamespace(returncode=0,stdout="")

    def test_nft_failure_does_not_claim_verified_cleanup(self):
        self.nft_error=True
        with self.assertRaisesRegex(RuntimeError,"cleanup failed"):
            self.trial.cleanup()
        self.restore.assert_called_once()
        self.assertIn(("systemctl","stop",self.trial.WORKER+".service"),self.calls)

    def test_deactivating_worker_with_pid_is_not_considered_stopped(self):
        self.stuck=True
        with self.assertRaisesRegex(RuntimeError,"worker_still_active"):
            self.trial.cleanup()
        self.restore.assert_called_once()

    def test_idempotent_cleanup_and_no_shared_service_stop(self):
        self.trial.cleanup();self.trial.cleanup()
        self.assertFalse(self.table)
        self.assertEqual(sum(call[:2]==("nft","delete") for call in self.calls),1)
        self.assertTrue((self.state/"cleanup-started").is_file())
        stops=[call for call in self.calls if call[:2]==("systemctl","stop")]
        self.assertTrue(all(call[-1]==self.trial.WORKER+".service" for call in stops))

    def test_listener_owned_by_different_pid_does_not_pass_readiness(self):
        self.assertTrue(self.trial.worker_ready())
        self.listener=self.listener.replace("pid=123,","pid=1234,")
        self.assertFalse(self.trial.worker_ready())

    def test_listener_on_wrong_local_address_does_not_pass_readiness(self):
        self.listener=self.listener.replace(self.trial.EDGE,"127.0.0.1")
        self.assertFalse(self.trial.worker_ready())

    def test_cleanup_marker_prevents_late_activation(self):
        (self.state/"cleanup-started").write_text("cleanup")
        with self.assertRaisesRegex(RuntimeError,"trial aborted"):
            with self.trial.mutation_guard():self.fail("must not activate after cleanup")
        self.assertFalse(self.calls)

    def test_stopped_worker_aborts_trial_monitor(self):
        self.worker.update(ActiveState="inactive",SubState="dead",MainPID="0")
        with self.assertRaisesRegex(RuntimeError,"not healthy"):
            self.trial.wait_trial(900)

    def test_cleanup_lock_serializes_independent_processes(self):
        code=("import sys;from pathlib import Path;"
              "sys.path.insert(0,sys.argv[1]);import meta_v15_phone_trial as t;"
              "t.STATE=Path(sys.argv[2]);print('started',flush=True);\n"
              "with t.state_lock(): (t.STATE/'child-done').write_text('done')\n")
        with self.trial.state_lock():
            process=subprocess.Popen([sys.executable,"-c",code,str(Path(__file__).resolve().parents[1]),
                                      str(self.state)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.addCleanup(lambda:process.poll() is None and process.kill())
            self.assertEqual(process.stdout.readline().strip(),"started")
            self.assertFalse((self.state/"child-done").exists())
            self.assertIsNone(process.poll())
        stdout,stderr=process.communicate(timeout=5)
        self.assertEqual(process.returncode,0,stderr)
        self.assertTrue((self.state/"child-done").is_file())


if __name__=="__main__":unittest.main()
