#!/usr/bin/env python3
"""Offline regression tests: all existing personalized DNS rules survive."""
import inspect
import ipaddress
import struct
import unittest
from unittest.mock import patch
from mnebydns_dns_policy_guard import (
    preserved,smoke_check,dns_a,PROTECTED_A,PIN,RESOLVER_BIND,
)

HEAD="tls://.:853 {\n    bind 89.125.90.101\n    reload 5s 1s\n"
TAIL="}\n"

def rule(name,kind="A",answer="188.120.254.223"):
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
        new=(HEAD+rule("personal.dns.mnebyvpn.site",answer="89.125.90.101")+self.google+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):preserved(self.base,new,scope="google")
    def test_google_only_change_requires_explicit_scope(self):
        new=(HEAD+self.personal+rule("www.youtube.com",answer="89.125.90.101")+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):preserved(self.base,new)
        self.assertTrue(preserved(self.base,new,scope="google")["preserved"])
    def test_google_scope_cannot_modify_similarly_named_customer_domain(self):
        customer=rule("mygoogleproduct.example.com")
        old=(HEAD+customer+self.google+self.nongoogle+TAIL).encode()
        new=(HEAD+rule("mygoogleproduct.example.com",answer="89.125.90.101")+self.google+self.nongoogle+TAIL).encode()
        with self.assertRaises(ValueError):
            preserved(old,new,scope="google")

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
        self.assertEqual(RESOLVER_BIND,"89.125.90.101")
        self.assertEqual(PIN,"188.120.254.223")
        self.assertEqual(inspect.signature(dns_a).parameters["address"].default,RESOLVER_BIND)
        result=smoke_check(resolver=lambda _: [PIN])
        self.assertEqual(result["protected_hosts_checked"],len(PROTECTED_A))
        self.assertEqual(result["expected_ipv4"],"188.120.254.223")
        self.assertEqual(result["resolver_bind"],"89.125.90.101")
        with self.assertRaises(RuntimeError):smoke_check(resolver=lambda _: ["1.1.1.1"])
        with self.assertRaises(RuntimeError):smoke_check(resolver=lambda _: ["89.125.90.101"])
    def test_dns_a_queries_local_bind_and_smoke_checks_ru_pin(self):
        seen=[]
        class FakeTls:
            def __init__(self):self._buf=b""
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def sendall(self,data):
                qid=struct.unpack("!H",data[2:4])[0]
                q=data[14:]
                pkt=struct.pack("!HHHHHH",qid,0x8180,1,1,0,0)+q+b"\xc0\x0c"+struct.pack("!HHIH",1,1,20,4)+ipaddress.IPv4Address("188.120.254.223").packed
                self._buf=struct.pack("!H",len(pkt))+pkt
            def recv(self,n):
                out,self._buf=self._buf[:n],self._buf[n:]
                return out
        class FakeSock:
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def settimeout(self,_):pass
        class FakeCtx:
            def wrap_socket(self,_sock,server_hostname):
                seen.append(("sni",server_hostname))
                return FakeTls()
        def connect(ep,timeout=4.0):
            seen.append(("connect",ep))
            return FakeSock()
        with patch("mnebydns_dns_policy_guard.socket.create_connection",side_effect=connect), \
             patch("mnebydns_dns_policy_guard.ssl.create_default_context",return_value=FakeCtx()):
            res=smoke_check()
        self.assertTrue(res["all_pinned"])
        self.assertTrue(all(v==("89.125.90.101",853) for k,v in seen if k=="connect"))
        self.assertTrue(all(v=="dns.mnebyvpn.site" for k,v in seen if k=="sni"))
    def test_policy_scope_must_be_known(self):
        with self.assertRaises(ValueError):preserved(self.base,self.base,scope="all")

if __name__=="__main__":
    unittest.main()
