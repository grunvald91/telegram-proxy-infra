"""Offline source-IP CoreDNS view isolation, no user/service changes."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from meta_v25_source_view import render, check_plugins, source_peer, VIEW_NAME, RU_EDGE, HOSTS

PLUGINS="acl any cache forward template tls view whoami"
CORE=("tls://.:853 {\n"
      "    template IN A gemini.google.com {\n"
      "        match ^gemini[.]google[.]com[.]$\n"
      "        answer \"{{ .Name }} 20 IN A 89.125.90.101\"\n"
      "    }\n"
      "    cache 30\n"
      "}\n")

class ScopedDNSViewTests(unittest.TestCase):
    def test_original_corefile_is_exact_suffix_and_meta_scoped_to_one_peer(self):
        plan=render(corefile=CORE,phone_ip="8.8.8.8",compiled_plugins=PLUGINS)
        plan.verify_rollback()
        self.assertTrue(plan.candidate.endswith(CORE))
        self.assertNotEqual(plan.candidate,CORE)
        self.assertEqual(plan.selected_source,"8.8.8.8")
        self.assertEqual(plan.selected_hosts,len(HOSTS))
        self.assertIn("view "+VIEW_NAME+" {\n",plan.candidate)
        self.assertIn("expr client_ip() == '8.8.8.8'",plan.candidate)
        self.assertEqual(plan.candidate.count('answer "{{ .Name }} 20 IN A '+RU_EDGE+'"'),len(HOSTS))
        self.assertEqual(plan.candidate.count("view "+VIEW_NAME),1)
        # Default (unfiltered) block after the view does not route any Meta host.
        ungated=plan.candidate[-len(CORE):]
        for name in HOSTS:
            self.assertNotIn(name,ungated)
        self.assertIn("gemini.google.com",ungated)

    def test_resilient_cache_baseline_supported(self):
        resilient=CORE.replace("    cache 30\\n", "    cache 30 {\\n        success 2048\\n    }\\n")
        plan=render(corefile=resilient,phone_ip="8.8.8.8",compiled_plugins=PLUGINS)
        plan.verify_rollback()
        self.assertTrue(plan.candidate.endswith(resilient))
        self.assertIn("view "+VIEW_NAME,plan.candidate)
        self.assertEqual(plan.selected_hosts,len(HOSTS))

    def test_view_must_be_compiled(self):
        for plugins in ("view tls", "template view", "acl template tls"):
            with self.subTest(plugins=plugins),self.assertRaisesRegex(RuntimeError,"lacks"):
                render(corefile=CORE,phone_ip="8.8.8.8",compiled_plugins=plugins)

    def test_invalid_phone_source_refused(self):
        for peer in ("0.0.0.0","127.0.0.1","10.0.0.8","192.168.1.8",
                     RU_EDGE,"89.125.90.101","8.8.8.8/32","not-an-ip"):
            with self.subTest(peer=peer),self.assertRaises(ValueError):
                render(corefile=CORE,phone_ip=peer,compiled_plugins=PLUGINS)

    def test_duplicate_dot_server_blocks_and_imports_fail_closed(self):
        with self.assertRaisesRegex(ValueError,"exactly one"):
            render(corefile=CORE+CORE,phone_ip="8.8.8.8",compiled_plugins=PLUGINS)
        with self.assertRaisesRegex(ValueError,"unambiguous"):
            render(corefile="# import secret.dns\n"+CORE,phone_ip="8.8.8.8",
                   compiled_plugins=PLUGINS)
        with self.assertRaisesRegex(ValueError,"already present"):
            render(corefile=CORE+"\n# "+VIEW_NAME,phone_ip="8.8.8.8",
                   compiled_plugins=PLUGINS)

    def test_renderer_starts_filtered_view_before_unchanged_fallback(self):
        plan=render(corefile=CORE,phone_ip="8.8.8.8",compiled_plugins=PLUGINS)
        first=plan.candidate.find("view "+VIEW_NAME)
        default=plan.candidate.rfind("tls://.:853 {")
        self.assertGreater(default,first)
        self.assertEqual(plan.candidate[default:],CORE)
        # These assertions are an offline structural contract, not live DoT proof.
        self.assertNotIn("view "+VIEW_NAME,CORE)

    def test_extra_unrelated_server_block_preserved_verbatim(self):
        remainder=("\nexample.net:15453 {\n"
                   "    forward . 1.1.1.1\n}\n")
        plan=render(corefile=CORE+remainder,phone_ip="8.8.8.8",compiled_plugins=PLUGINS)
        self.assertTrue(plan.candidate.endswith(CORE+remainder))
        self.assertIn(remainder,plan.candidate)

if __name__=="__main__": unittest.main()
