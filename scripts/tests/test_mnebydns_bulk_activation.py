#!/usr/bin/env python3
"""Offline safety contracts for mass Smart DNS release. No server calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
def load(name, file):
    spec=importlib.util.spec_from_file_location(name, ROOT/"scripts"/file)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

deploy=load("test_bulk_deploy","mnebydns-bulk-deploy-20261112.py")
verify=load("test_bulk_verify","mnebydns-bulk-remote-verify-20261112.py")
policy=deploy.renderer

class BulkContracts(unittest.TestCase):
    def sample(self):
        core=("tls://.:853 {\n"
              "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
              "    cache 30\n}\n")
        nginx=("stream {\nmap $ssl_preread_server_name $direct_mtproxy_backend {\n"
               " default 127.0.0.1:9443;\n}\n"
               "server { proxy_pass $direct_mtproxy_backend; }\n}\n")
        return core,nginx
    def test_manifest_additive_and_mutation_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            work=root/"work";base=root/"base"
            work.mkdir();base.mkdir()
            shutil.copy(ROOT/"scripts/mnebydns-owner-domain-render-20261110.py",
                        work/"mnebydns-owner-domain-render-20261110.py")
            items=[("example.org","93.184.215.14"),("demo.example.net","93.184.215.14")]
            core,nginx=self.sample()
            c,n=core,nginx
            for host,ip in items:
                c=policy.core_add(c,host)
                n=policy.nginx_add(n,host,ip)
            for name,value in (("dns.before",core),("nginx.before",nginx),
                               ("dns.pilot",c),("nginx.pilot",n)):
                (base/name).write_text(value)
            expected={"eligible":len(items),"no_live_mutations":True,
                      "source_sha256":{"core":verify.sha(core),"nginx":verify.sha(nginx)},
                      "target_sha256":{"core":verify.sha(c),"nginx":verify.sha(n)}}
            (work/"expected.json").write_text(json.dumps(expected))
            (work/"manifest.tsv").write_text("".join(h+"\t"+ip+"\n" for h,ip in items))
            verify.check(work,base)
            (base/"nginx.pilot").write_text(n+"# TAMPER\n")
            with self.assertRaisesRegex(RuntimeError,"pilot"):
                verify.check(work,base)
            (base/"nginx.pilot").write_text(n)
            (work/"manifest.tsv").write_text("example.org\t169.254.169.254\n")
            with self.assertRaises(Exception):
                verify.check(work,base)
    def test_ru_https_request_uses_real_crlf_and_safe_source(self):
        src=deploy.RU_HTTPS
        self.assertIn(r"\r\nHost:",src)
        self.assertNotIn(r"\\r\\nHost:",src)
        self.assertIn("base64",src)
        compile(src,"<secure RU probe>","exec")
    def test_atomic_sql_and_no_false_subset_success(self):
        sql=deploy.atomic_update_sql([("example.org","93.184.215.14"),
                                      ("demo.example.net","93.184.215.14")])
        self.assertIn("modified<>2",sql)
        self.assertIn("matched<>2",sql)
        self.assertIn("RAISE EXCEPTION 'BULK_DB_CAS_LOST'",sql)
        self.assertIn("revision=revision+1",sql)
        self.assertIn("verified_origin_ip=inputs.ip::inet",sql)
        self.assertNotIn("TRUNCATE",sql)
    def test_existing_owner_rollback_sentinel_is_prepared(self):
        stage=(ROOT/"scripts/mnebydns-bulk-stage-20261112.sh").read_text()
        self.assertIn('"$base/domain"',stage)
        self.assertIn('systemctl enable --now "$name.timer"',stage)
        self.assertIn('trap abort EXIT',stage)
        self.assertIn('python3 "$work/mnebydns-bulk-remote-verify-20261112.py"',stage)
        self.assertLess(stage.index('systemctl enable --now "$name.timer"'),
                        stage.index('mv -f "$nginx.owner-stage-$id" "$nginx"'))
        self.assertLess(stage.index('python3 "$work/mnebydns-bulk-remote-verify-20261112.py"'),
                        stage.index('systemctl enable --now "$name.timer"'))
        deploy_source=(ROOT/"scripts/mnebydns-bulk-deploy-20261112.py").read_text()
        self.assertIn('committed or owner.is_confirmed(run)',deploy_source)
        self.assertIn('status = status_class(selected)',deploy_source)
        compensator=(ROOT/"scripts/mnebydns-bulk-compensate-20261112.sh").read_text()
        self.assertIn('cmp -s "$base/dns.pilot" "$live_dns"',compensator)
        self.assertIn('cmp -s "$base/nginx.pilot" "$live_nginx"',compensator)
        self.assertNotIn('test -f "$base/confirmed"',compensator)

if __name__=="__main__":
    unittest.main()
