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
        self.assertIn("iglite_v11_transport=ROUTE_ONLY_NO_SYSCTL_NO_NFT",self.src)

    def test_distinct_run_state_and_independent_same_boot_restore(self):
        self.assertIn("mneby-iglite-wifi-de-20261111-v11",self.src)
        self.assertIn("mneby-ig-lite-route-only-20261111-v11",self.src)
        self.assertIn('base.command(["systemd-run"',self.src)
        self.assertIn("base.MUTATION_MARKER",self.src)
        self.assertIn("finally:\n        rollback()",self.src)
        self.assertNotIn("base.rollback()",self.src)
        self.assertIn("iglite_v11_rollback=ALREADY_RESTORED_NO_RESTART",self.src)
        self.assertIn("iglite_v11_rollback=VERIFIED_CONFIGS_AND_SERVICES_NO_TCP_WRITES",self.src)
        self.assertIn("base.WATCHDOG_SECONDS",self.src)
        self.assertIn("base.TRIAL_SECONDS+base.MIN_ROLLBACK_MARGIN",self.src)

    def test_workflow_disarmed_and_not_triggered_by_code_changes(self):
        wf=self.workflow
        self.assertEqual(wf.count("if: ${{ false }}"),2)
        self.assertNotIn("if: ${{ true }}",wf)
        self.assertIn("ops/mnebydns-iglite-v11-launch.marker",wf)
        self.assertNotIn("'ops/mnebydns-iglite-wifi-v10-launch.marker'",wf)
        self.assertIn("mnebydns_iglite_route_only_v11.py",wf)
        self.assertIn("MNEBY_IGLITE_V11_ROUTE_ONLY_APPROVED=YES",wf)
        self.assertIn("ws=='1'",wf)
        self.assertIn("nft_status!=0",wf)
        self.assertNotIn("tcp window set 20",wf)
        self.assertNotIn("net.ipv4.tcp_window_scaling=0",wf)

    def test_in_memory_only_no_pcap_files(self):
        self.assertIn("mnebydns_iglite_sni_observer import begin,finish,summary",self.src)
        self.assertNotIn("PCAP.write(",self.src)
        self.assertNotIn("tcpdump",self.src)
        self.assertIn("iglite_v11_end_to_end_android=NOT_PROVEN",self.src)

if __name__=="__main__":
    unittest.main()
