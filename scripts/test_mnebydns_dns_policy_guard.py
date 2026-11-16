#!/usr/bin/env python3
"""Offline regression tests: all existing personalized DNS rules survive."""
import unittest
from unittest.mock import Mock
from mnebydns_dns_policy_guard import preserved,smoke_check,PROTECTED_A,PIN

HEAD="tls://.:853 {\n    bind 89.125.90.101\n    reload 5s 1s\n"
TAIL="}\n"

def rule(name,kind="A",answer="89.125.90.101"):
    return ("    template IN "+kind+" "+name+" {\n"
           "        match ^"+name.replace(".","[.]")+"[.]$\n"
           '        answer "{{ .Name }} 20 IN A '+answer+'"\n'
           "        fallthrough\n    }\n")

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.personal=rule("personal.dns.mnebyvpn.site")
        self.google=rule("www.youtube.com")
        self.nongoogle=rule("claude.ai")
        self.base=(HEAD+self.personal+self.google+self.nongoogle+TAIL).encode()
    def test_allow_only_additive_blocks(self):
        new=(HEAD+self.personal+self.google+self.nongoogle+rule("new.example.com")+TAIL).encode()
        self.assertTrue(preserved(self.base,new)["preserved"])
    def test_reject_personal_template_removed(self):
        new=(HEAD+self.google+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):preserved(self.base,new)
    def test_reject_personal_template_changed_even_google_scope(self):
        new=(HEAD+rule("personal.dns.mnebyvpn.site",answer="188.120.254.223")+self.google+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):preserved(self.base,new,scope="google")
    def test_google_only_change_requires_explicit_scope(self):
        new=(HEAD+self.personal+rule("www.youtube.com",answer="188.120.254.223")+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):preserved(self.base,new)
        self.assertTrue(preserved(self.base,new,scope="google")["preserved"])
    def test_owner_domain_exact_removal_can_be_allowed(self):
        owner=rule("oracle.com")
        old=(HEAD+self.personal+self.google+owner+TAIL).encode()
        updated=(HEAD+self.personal+self.google+TAIL).encode()
        with self.assertRaises(ValueError):preserved(old,updated)
        self.assertTrue(preserved(old,updated,scope="owner",owner_domain="oracle.com")["preserved"])
        with self.assertRaises(ValueError):preserved(old,updated,scope="owner",owner_domain="wrong.com")
    def test_bind_and_reload_cannot_be_removed(self):
        new=(HEAD.replace("    reload 5s 1s\n","")+self.personal+self.google+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):preserved(self.base,new)
    def test_unmatched_personal_template_cannot_be_ignored(self):
        broken=self.base.decode().replace("    }", "", 1).encode()
        with self.assertRaises(ValueError):
            preserved(self.base,broken)

    def test_empty_unparseable_config_is_rejected(self):
        with self.assertRaises(ValueError):preserved(b"bad",b"bad",scope="google")
    def test_google_and_ai_probe_failure_fails_closed(self):
        self.assertEqual(smoke_check(resolver=lambda _: [PIN])["protected_hosts_checked"],len(PROTECTED_A))
        with self.assertRaises(RuntimeError):smoke_check(resolver=lambda _: ["1.1.1.1"])
    def test_policy_scope_must_be_known(self):
        with self.assertRaises(ValueError):preserved(self.base,self.base,scope="all")

if __name__=="__main__":
    unittest.main()
