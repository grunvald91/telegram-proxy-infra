#!/usr/bin/env python3
"""Static v11 safety contracts: no remote service/netfilter mutations in CI."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"mnebydns_iglite_route_only_v11.py"
WF=ROOT.parent/".github/workflows/mnebydns-iglite-wifi-v10-onrequest.yml"

class V11RouteOnlySafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=SCRIPT.read_text()
        cls.tree=ast.parse(cls.src)
        cls.workflow=WF.read_text()

    def test_never_mutates_global_tcp_or_nftables(self):
        text=self.src
        self.assertNotIn("net.ipv4.tcp_window_scaling=0",text)
        self.assertNotIn("tcp window set",text)
        self.assertNotIn("nft_rules(",text)
        self.assertNotIn("base.live()",text)
        self.assertNotIn('sysctl","-w"',text)
        for node in ast.walk(self.tree):
            if not isinstance(node,ast.Call):continue
            if not isinstance(node.func,ast.Attribute) or node.func.attr!="command":continue
            if not node.args or not isinstance(node.args[0],ast.List):continue
            parts=[]
            for item in node.args[0].elts:
                if isinstance(item,ast.Constant) and isinstance(item.value,str):
                    parts.append(item.value)
            if parts:
                self.assertNotIn(parts[0],("sysctl","iptables","ip6tables","tc"))
                if parts[0]=="nft":
                    self.assertEqual(parts[1],"list")

    def test_only_exact_hostnames_and_byte_reversible_route_renderer(self):
        self.assertIn("for hostname in base.HOSTS:",self.src)
        self.assertIn("m.nginx_add(ng,hostname,origin)",self.src)
        self.assertIn("m.core_add(core,hostname)",self.src)
        self.assertIn("m.nginx_remove(reverse_ng,hostname)",self.src)
        self.assertIn("m.core_remove(reverse_core,hostname)",self.src)
        self.assertIn("byte-reversible",self.src)
        self.assertIn("check_exact_types(host=hostname)",self.src)
        self.assertIn('TRANSPORT_LABEL = "ROUTE_ONLY_NO_SYSCTL_NO_NFT"',self.src)

    def test_distinct_run_state_and_independent_same_boot_restore(self):
        self.assertIn("mneby-iglite-wifi-de-20261111-v11",self.src)
        self.assertIn("mneby-ig-lite-route-only-20261111-v11",self.src)
        self.assertIn('base.command(["systemd-run"',self.src)
        self.assertIn("base.MUTATION_MARKER",self.src)
        self.assertIn("try:\n            rollback()",self.src)
        self.assertNotIn("base.rollback()",self.src)
        self.assertIn("iglite_v11_rollback=ALREADY_RESTORED_NO_RESTART",self.src)
        self.assertIn("iglite_v11_rollback=VERIFIED_CONFIGS_AND_SERVICES_NO_TCP_WRITES",self.src)
        self.assertIn("base.WATCHDOG_SECONDS",self.src)
        self.assertIn("base.TRIAL_SECONDS+base.MIN_ROLLBACK_MARGIN",self.src)

    def test_workflow_armed_only_by_new_v11_launch_marker(self):
        wf=self.workflow
        self.assertEqual(wf.count("if: ${{ true }}"),2)
        self.assertNotIn("if: ${{ false }}",wf)
        self.assertIn("ops/mnebydns-iglite-v11-launch.marker",wf)
        self.assertNotIn("'ops/mnebydns-iglite-wifi-v10-launch.marker'",wf)
        self.assertIn("mnebydns_iglite_route_only_v11.py",wf)
        self.assertIn("MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED=YES",wf)
        self.assertIn("ws=='1'",wf)
        self.assertIn("nft_status!=0",wf)
        self.assertNotIn("tcp window set 20",wf)
        self.assertNotIn("net.ipv4.tcp_window_scaling=0",wf)

    def test_mocked_rollback_restores_only_configs_and_second_run_is_noop(self):
        import importlib.util
        import sys
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        sys.path.insert(0,str(ROOT))
        spec=importlib.util.spec_from_file_location("route_only_rollback_test",SCRIPT)
        v=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(v)
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            root=home/"durable";root.mkdir()
            (root/"mutation-ready").write_bytes(b"armed\n")
            original={"core":b"original-core\n","nginx":b"original-nginx\n"}
            modified={"core":b"modified-core\n","nginx":b"modified-nginx\n"}
            for kind in ("core","nginx"):
                (root/(kind+".original")).write_bytes(original[kind])
                (root/(kind+".candidate")).write_bytes(modified[kind])
            core=home/"Corefile";core.write_bytes(modified["core"])
            nginx=home/"nginx.conf";nginx.write_bytes(modified["nginx"])
            ws=home/"tcp_window_scaling";ws.write_text("1\n")
            calls=[]
            def fake_command(args,**kwargs):
                calls.append(tuple(args))
                status=1 if args[:3]==["nft","list","table"] else 0
                return SimpleNamespace(returncode=status)
            with (patch.object(v.base,"ROOT",root),
                  patch.object(v.base,"CORE",core),
                  patch.object(v.base,"NGINX",nginx),
                  patch.object(v.base,"WSFILE",ws),
                  patch.object(v.base,"command",side_effect=fake_command)):
                v.rollback()
                self.assertEqual(core.read_bytes(),original["core"])
                self.assertEqual(nginx.read_bytes(),original["nginx"])
                restarts=sum(c[0]=="systemctl" and c[1] in ("restart","reload") for c in calls)
                self.assertEqual(restarts,2)
                v.rollback()
                self.assertEqual(sum(c[0]=="systemctl" and c[1] in ("restart","reload")
                                     for c in calls),2)
                self.assertFalse(any(c[0] in ("sysctl","iptables","tc") for c in calls))
                self.assertFalse(any(c[0]=="nft" and c[1]!="list" for c in calls))

    def test_old_v10_global_window20_live_entrypoint_is_retired(self):
        old=(ROOT/"mnebydns_iglite_wifi_multi_meta_v10_w20.py").read_text()
        self.assertIn("Legacy v10 global TCP Window20 trial disabled",old)
        self.assertIn('if sys.argv[1]=="rollback":',old)
        self.assertIn('rollback(boot=True)',old)

    def test_in_memory_only_no_pcap_files(self):
        self.assertIn("mnebydns_iglite_sni_observer import begin,finish,summary",self.src)
        self.assertNotIn("PCAP.write(",self.src)
        self.assertNotIn("tcpdump",self.src)
        self.assertIn("iglite_v11_end_to_end_android=NOT_PROVEN",self.src)

class V11RuntimeFailures(unittest.TestCase):
    def setUp(self):
        import importlib.util
        import sys
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        sys.path.insert(0,str(ROOT))
        spec=importlib.util.spec_from_file_location("v11_failures",SCRIPT)
        self.v=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.v)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        home=Path(self.tmp.name);root=home/"state";root.mkdir()
        self.root=root
        (root/"mutation-ready").write_bytes(b"armed\n")
        self.paths={}
        for key in ("core","nginx"):
            (root/(key+".original")).write_bytes((key+"-original").encode())
            (root/(key+".candidate")).write_bytes((key+"-candidate").encode())
            self.paths[key]=home/key
            self.paths[key].write_bytes((key+"-candidate").encode())
        ws=home/"ws";ws.write_text("1\n")
        self.calls=[]
        def command(args,**kwargs):
            self.calls.append(tuple(args))
            return SimpleNamespace(returncode=1 if args[0]=="nft" else 0)
        for name,value in (("ROOT",root),("CORE",self.paths["core"]),
                           ("NGINX",self.paths["nginx"]),("WSFILE",ws)):
            p=patch.object(self.v.base,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(self.v.base,"command",side_effect=command)
        p.start();self.addCleanup(p.stop)

    def test_external_drift_is_checked_before_either_file_is_written(self):
        for drifted in ("core","nginx"):
            for key,path in self.paths.items():path.write_bytes((key+"-candidate").encode())
            self.paths[drifted].write_bytes(b"external-change")
            before={key:path.read_bytes() for key,path in self.paths.items()}
            with self.assertRaisesRegex(RuntimeError,"restoration incomplete"):
                self.v.rollback()
            self.assertEqual(before,{key:path.read_bytes() for key,path in self.paths.items()})
            self.assertFalse(any(c[:2] in (("systemctl","restart"),("systemctl","reload"))
                                 for c in self.calls))

    def test_restore_write_failure_still_reloads_successfully_restored_file(self):
        from unittest.mock import patch
        real=self.v.base.atomic_replace
        def replace(path,data):
            if path==self.paths["core"]:raise OSError("simulated write failure")
            real(path,data)
        with patch.object(self.v.base,"atomic_replace",side_effect=replace):
            with self.assertRaisesRegex(RuntimeError,"recovery verification"):
                self.v.rollback()
        self.assertEqual(self.paths["nginx"].read_bytes(),b"nginx-original")
        self.assertIn(("systemctl","reload","nginx.service"),self.calls)

    def test_v10_timer_service_or_table_blocks_v11(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        for active in (".timer",".service","table"):
            def command(args,**kwargs):
                hit=(args[0]=="nft" if active=="table" else args[-1].endswith(active))
                return SimpleNamespace(returncode=0 if hit else 3)
            with patch.object(self.v.base,"command",side_effect=command):
                with self.assertRaisesRegex(RuntimeError,"v10"):
                    self.v.check_retired_v10()

    def test_term_and_hup_unwind_to_finally_restoration(self):
        import signal
        for sig in (signal.SIGTERM,signal.SIGHUP):
            for key,path in self.paths.items():path.write_bytes((key+"-candidate").encode())
            with self.assertRaises(SystemExit) as result:
                try:self.v.interrupted(sig,None)
                finally:self.v.rollback()
            self.assertEqual(result.exception.code,128+sig)
            for key,path in self.paths.items():
                self.assertEqual(path.read_bytes(),(key+"-original").encode())

    def test_live_term_stops_capture_and_restores_before_exit(self):
        self._live_failure(before_ready=False)

    def test_readiness_failure_stops_capture_and_restores(self):
        self._live_failure(before_ready=True)

    def _live_failure(self,*,before_ready):
        from contextlib import ExitStack
        import os
        import shutil
        import signal
        from types import SimpleNamespace
        from unittest.mock import Mock,patch
        import mnebydns_iglite_dns_wire_checks as wire
        import mnebydns_iglite_sni_observer as observer
        shutil.rmtree(self.root)
        originals={key:path.read_bytes() for key,path in self.paths.items()}
        renderer=SimpleNamespace(
            origin_ip=lambda host:"157.240.0.160",
            nginx_add=lambda text,*args:text+"-new",
            core_add=lambda text,*args:text+"-new",
            nginx_remove=lambda text,*args:text.removesuffix("-new"),
            core_remove=lambda text,*args:text.removesuffix("-new"))
        proc=Mock();proc.poll.return_value=None
        finish=Mock(return_value=object())
        live_check=Mock(side_effect=[None,RuntimeError("synthetic readiness failure")]) if before_ready else None
        previous=signal.getsignal(signal.SIGTERM)
        with ExitStack() as stack:
            for target,name,value in (
                (self.v,"check_retired_v10",Mock()),
                (self.v,"LIVE_CHECK",live_check),
                (self.v.base,"baseline",lambda:(originals["nginx"],originals["core"])),
                (self.v.base,"owner",lambda:renderer),
                (self.v.base,"HOSTS",("i.instagram.com",)),
                (self.v.base,"live_tls",lambda:"TLSv1.3"),
                (wire,"check_exact_types",lambda **kw:{"A":"A_EXACT_DE"}),
                (observer,"begin",lambda hosts:(proc,Mock(),object(),[])),
                (observer,"finish",finish),(observer,"summary",Mock()),
                (self.v.time,"sleep",lambda seconds:signal.raise_signal(signal.SIGTERM)),
            ):
                stack.enter_context(patch.object(target,name,value))
            stack.enter_context(patch.dict(os.environ,{"MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED":"YES"}))
            with self.assertRaises(RuntimeError if before_ready else SystemExit) as result:self.v.live()
        if before_ready:self.assertIn("synthetic readiness",str(result.exception))
        else:self.assertEqual(result.exception.code,128+signal.SIGTERM)
        finish.assert_called_once()
        self.assertEqual(signal.getsignal(signal.SIGTERM),previous)
        for key,path in self.paths.items():self.assertEqual(path.read_bytes(),originals[key])

if __name__=="__main__":
    unittest.main()

