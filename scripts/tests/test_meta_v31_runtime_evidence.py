"""Runtime recovery faults and actual packet-derived SNI verdict regressions."""
from contextlib import ExitStack,redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import meta_v26_de_stage as de
import meta_v26_ru_stage as ru
import meta_v30_actions_adapter as adapter
import meta_v31_sni_evidence as evidence
import meta_v15_receive_window as receiver
import mnebydns_iglite_dns_wire_checks as wire
from mnebydns_iglite_sni_observer import parse_pcap
from test_mnebydns_iglite_sni_observer import tls_hello,packet,make_pcap,fragment_records

class RuntimeRecoveryTests(unittest.TestCase):
    def fixture(self,stack):
        temp=stack.enter_context(tempfile.TemporaryDirectory())
        p=Path(temp);root=p/"state";root.mkdir()
        live={key:p/key for key in ("dns","nginx")}
        for key,path in live.items():
            (root/(key+".original")).write_bytes(b"BASELINE")
            (root/(key+".candidate")).write_bytes(b"EXPERIMENT")
            path.write_bytes(b"EXPERIMENT")
        (root/"armed").write_bytes(b"armed")
        stack.enter_context(patch.object(de,"ROOT",root))
        stack.enter_context(patch.object(de,"LIVE_DNS",live["dns"]))
        stack.enter_context(patch.object(de,"LIVE_NGINX",live["nginx"]))
        stack.enter_context(patch.object(de,"flag"))
        stack.enter_context(patch.object(de,"active",side_effect=lambda s:s in
            ("nginx.service","mnebydns-dot.service")))
        return root,live

    def test_failed_reload_is_retried_before_reset_forgets_recovery(self):
        with ExitStack() as stack:
            root,live=self.fixture(stack)
            runtime={key:b"EXPERIMENT" for key in live};attempts=[]
            def command(args,**kwargs):
                if args[:2]==["systemctl","restart"]:runtime["dns"]=live["dns"].read_bytes()
                if args[:2]==["systemctl","reload"]:
                    attempts.append(args)
                    if len(attempts)==1:raise subprocess.TimeoutExpired(args,25)
                    runtime["nginx"]=live["nginx"].read_bytes()
                return SimpleNamespace(returncode=0,stdout="")
            stack.enter_context(patch.object(de,"cmd",side_effect=command))
            with self.assertRaisesRegex(RuntimeError,"nginx_restore"):de._rollback_locked()
            self.assertEqual(live["nginx"].read_bytes(),b"BASELINE")
            self.assertEqual(runtime["nginx"],b"EXPERIMENT")
            self.assertTrue((root/"nginx.restore-pending").is_file())
            de.reset()
            self.assertEqual(runtime["nginx"],b"BASELINE")
            self.assertEqual(len(attempts),2)
            self.assertFalse(root.exists())

    def test_persistent_reload_failure_keeps_checkpoint_and_pending_marker(self):
        with ExitStack() as stack:
            root,live=self.fixture(stack)
            def command(args,**kw):
                if args[:2]==["systemctl","reload"]:raise RuntimeError("still failing")
                return SimpleNamespace(returncode=0,stdout="")
            stack.enter_context(patch.object(de,"cmd",side_effect=command))
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError,"nginx_restore"):de.reset()
                self.assertTrue((root/"nginx.original").is_file())
                self.assertTrue((root/"nginx.restore-pending").is_file())

    def test_dns_restore_write_failure_does_not_skip_nginx_restore(self):
        with ExitStack() as stack:
            root,live=self.fixture(stack)
            real=de.replace;calls=[]
            def replace(path,data):
                if path==live["dns"]:raise OSError("disk write failed")
                real(path,data)
            stack.enter_context(patch.object(de,"replace",side_effect=replace))
            stack.enter_context(patch.object(de,"cmd",side_effect=lambda args,**kw:
                calls.append(args) or SimpleNamespace(returncode=0,stdout="")))
            with self.assertRaisesRegex(RuntimeError,"dns_restart"):de._rollback_locked()
            self.assertEqual(live["nginx"].read_bytes(),b"BASELINE")
            self.assertIn(["systemctl","reload","nginx.service"],calls)
            self.assertTrue((root/"dns.restore-pending").exists())

    def test_selective_dns_disable_retries_failed_restart_with_equal_files(self):
        with ExitStack() as stack:
            root,live=self.fixture(stack);attempts=[]
            def command(args,**kwargs):
                if args[:2]==["systemctl","restart"]:
                    attempts.append(args)
                    if len(attempts)==1:raise RuntimeError("restart failed")
                return SimpleNamespace(returncode=0,stdout="")
            stack.enter_context(patch.object(de,"cmd",side_effect=command))
            with self.assertRaises(RuntimeError):de.disable_dns()
            self.assertEqual(live["dns"].read_bytes(),b"BASELINE")
            self.assertTrue((root/"dns.restore-pending").exists())
            de.disable_dns()
            self.assertEqual(len(attempts),2)
            self.assertFalse((root/"dns.restore-pending").exists())

    def test_dead_de_services_cannot_pass_adapter_health(self):
        with ExitStack() as stack:
            root,live=self.fixture(stack)
            stack.enter_context(patch.object(de,"active",side_effect=lambda s:s==de.UNIT+".timer"))
            stack.enter_context(patch.object(wire,"read_exact_dot_type",return_value="A_EXACT_DE"))
            output=io.StringIO()
            with redirect_stdout(output):de.status()
            remote=object.__new__(adapter.Remote)
            remote.run=lambda role,action:output.getvalue() if role=="de" else "\n".join(adapter.HEALTH["ru"])
            with self.assertRaisesRegex(RuntimeError,"nginx_active=false|nginx_active=true"):
                remote.verify_health()

    def test_live_dot_failure_propagates_instead_of_healthy_file_only_status(self):
        with ExitStack() as stack:
            self.fixture(stack)
            stack.enter_context(patch.object(wire,"read_exact_dot_type",side_effect=TimeoutError("DoT stalled")))
            with self.assertRaises(TimeoutError):de.status()

class PacketEvidenceTests(unittest.TestCase):
    def collector(self,*,split=True,fragmented=False,overlap=False):
        collector=evidence.CaptureEvidence("8.8.8.8",Path("unused.json"))
        hello=tls_hello()
        if fragmented:hello=fragment_records(hello,(30,))
        packets=[packet(100,2)]
        if overlap:
            packets.extend((packet(101,24,hello[:75]),packet(101,24,hello)))
        elif split:
            packets.extend(packet(101+i,24,hello[i:i+8]) for i in range(0,len(hello),8))
        else:packets.append(packet(101,24,hello))
        parse_pcap(make_pcap(packets),collector.analyzer)
        collector.finished=True;collector.drops=0
        return collector

    def test_real_packet_boundaries_produce_split_verdict_for_record_variants(self):
        for fragmented in (False,True):
            report=self.collector(fragmented=fragmented).report()
            evidence.validate_report(report,final=True)
            self.assertEqual(report["verdict"],"SNI_SEGMENTATION_OBSERVED")
            self.assertEqual(report["stats"]["sni_split"],1)
            self.assertEqual(report["android_login_feed"],"NOT_VERIFIED")

    def test_unsplit_and_overlapping_retransmissions_never_pass(self):
        for collector,label in ((self.collector(split=False),"UNSPLIT_SNI_OBSERVED"),
                                (self.collector(overlap=True),"SEGMENTATION_INDETERMINATE")):
            report=collector.report()
            self.assertEqual(report["verdict"],label)
            with self.assertRaises(RuntimeError):evidence.validate_report(report,final=True)

    def test_no_phone_traffic_is_not_a_success(self):
        collector=self.collector();collector.analyzer=evidence.Analyzer(evidence.HOSTS)
        report=collector.report()
        with self.assertRaisesRegex(RuntimeError,"NO_TARGET_CLIENTHELLO"):
            evidence.validate_report(report,final=True)

    def test_capture_failure_or_kernel_drops_override_positive_splits(self):
        for drops,failures in ((1,[]),(None,[]),(0,["UnexpectedCaptureEOF"])):
            collector=self.collector();collector.drops=drops;collector.failures=failures
            with self.assertRaises(RuntimeError):evidence.validate_report(collector.report(),final=True)

    def test_live_counter_cannot_be_used_as_a_final_capture(self):
        report=self.collector().report();report["final"]=False
        with self.assertRaisesRegex(RuntimeError,"CAPTURING"):
            evidence.validate_report(report,final=True)

    def test_stale_observer_never_passes_live_health(self):
        report=self.collector().report();report["updated_at"]=time.time()-30
        with self.assertRaisesRegex(RuntimeError,"stale"):evidence.validate_report(report)

    def test_finished_report_can_be_collected_after_service_teardown(self):
        report=self.collector().report();report["updated_at"]=time.time()-80
        evidence.validate_report(report,final=True)

    def test_capture_must_report_zero_kernel_drops_at_finalization(self):
        for diagnostic,valid in ((b"3 packets captured\n0 packets dropped by kernel\n",True),
                                 (b"3 packets captured\n",False),
                                 (b"3 packets captured\n2 packets dropped by kernel\n",False)):
            collector=self.collector();collector.finished=False
            collector.process=Mock();collector.process.poll.return_value=None
            collector.process.wait.return_value=0
            collector.process.stderr.read.return_value=diagnostic
            collector.thread=Mock();collector.thread.is_alive.return_value=False
            collector.stop()
            if valid:evidence.validate_report(collector.report(),final=True)
            else:
                with self.assertRaises(RuntimeError):evidence.validate_report(collector.report(),final=True)

    def test_early_clean_capture_eof_is_rejected(self):
        collector=evidence.CaptureEvidence("8.8.8.8",Path("unused.json"))
        process=Mock();process.poll.return_value=0;process.wait.return_value=0
        process.stderr.read.return_value=b"0 packets dropped by kernel\n"
        def clean_eof(stream,analyzer,ready):ready.set()
        with patch.object(evidence.subprocess,"Popen",return_value=process),\
             patch.object(evidence,"parse_pcap",side_effect=clean_eof):
            with self.assertRaisesRegex(RuntimeError,"did not become ready"):collector.start()

    def test_evidence_has_no_peer_address_or_packet_payload(self):
        report=self.collector().report()
        encoded=json.dumps(report)
        self.assertNotIn("8.8.8.8",encoded)
        self.assertNotIn('"payload":',encoded)
        self.assertFalse(report["pcap_written"])

    def test_failed_evidence_is_saved_before_validation_raises(self):
        with tempfile.TemporaryDirectory() as d:
            remote=object.__new__(adapter.Remote);remote.env={"RUNNER_TEMP":d}
            report=self.collector(split=False).report()
            remote.run=lambda role,action:json.dumps(report)
            with self.assertRaisesRegex(RuntimeError,"UNSPLIT"):
                remote.collect_evidence(final=True,require_success=True)
            saved=Path(d)/"meta-v31-evidence/phone-sni.json"
            self.assertEqual(json.loads(saved.read_text())["verdict"],report["verdict"])

class BackendAndWorkflowTests(unittest.TestCase):
    def test_worker_captures_before_listening_and_finalizes_after_closing(self):
        import threading
        from collections import Counter
        actions=[]
        proxy=SimpleNamespace(stop=threading.Event(),stats=Counter())
        proxy.stop.set()
        proxy.start=lambda:actions.append("listen")
        proxy.close=lambda:actions.append("close")
        capture=Mock()
        capture.start.side_effect=lambda:actions.append("capture")
        capture.stop.side_effect=lambda:actions.append("finalize")
        capture.publish.side_effect=lambda stats:actions.append("publish")
        args=["receiver","--edge",ru.RU_EDGE,"--peer","8.8.8.8",
              "--backend-address",ru.WG_BACKEND,"--non-meta-backend-address",ru.RU_EDGE,
              "--evidence-file","/var/lib/mneby-meta-v26-ru/evidence.json"]
        with patch.object(sys,"argv",args),patch.object(receiver,"WindowProxy",return_value=proxy),\
             patch.object(receiver.signal,"signal"),\
             patch.object(evidence,"CaptureEvidence",return_value=capture):
            receiver.main()
        self.assertEqual(actions,["capture","listen","close","finalize","publish"])

    def test_live_backend_must_stay_on_wireguard(self):
        with patch.object(ru,"cmd",return_value=SimpleNamespace(stdout='[{"dev":"ens3"}]')):
            with self.assertRaisesRegex(RuntimeError,"left the private WireGuard"):
                ru.verify_tls_path(("i.instagram.com",))

    def test_wg_probe_requires_hostname_certificate_for_each_requested_host(self):
        raw=Mock();tls=Mock();tls.getpeercert.return_value={"subject":"verified"}
        class Context:
            def __enter__(self):return raw
            def __exit__(self,*args):pass
        class TlsContext(Context):
            def __enter__(self):return tls
        ctx=Mock();ctx.wrap_socket.return_value=TlsContext()
        with patch.object(ru,"cmd",return_value=SimpleNamespace(stdout='[{"dev":"tg-relay"}]')),\
             patch.object(ru.socket,"create_connection",return_value=Context()) as dial,\
             patch.object(ru.ssl,"create_default_context",return_value=ctx):
            hosts=("i.instagram.com","iglite-z.instagram.com")
            self.assertEqual(ru.verify_tls_path(hosts),2)
            self.assertEqual({c.kwargs["server_hostname"] for c in ctx.wrap_socket.call_args_list},set(hosts))
            self.assertTrue(all(c.args[0]==(ru.WG_BACKEND,443) for c in dial.call_args_list))
            tls.getpeercert.return_value={}
            with self.assertRaisesRegex(RuntimeError,"certificate missing"):ru.verify_tls_path(hosts)

    def test_workflow_exposes_thirty_minutes_and_has_teardown_budget(self):
        import ast,re
        path=Path(__file__).resolve().parents[2]/".github/workflows/meta-v30-manual-two-server-canary.yml"
        text=path.read_text()
        duration=text.split("      duration_minutes:\n",1)[1].split("permissions:",1)[0]
        options=ast.literal_eval(re.search(r"(?m)^        options: (.+)$",duration)[1])
        self.assertIn("30",options)
        self.assertRegex(duration,r"(?m)^        default: '30'$")
        self.assertGreaterEqual(int(re.search(r"timeout-minutes: (\d+)",text)[1]),40)
        self.assertIn(adapter.APPROVAL,text)

if __name__=="__main__":unittest.main()
