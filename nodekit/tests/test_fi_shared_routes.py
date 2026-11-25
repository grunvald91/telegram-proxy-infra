import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_shared_routes import parse,render_core,render_nginx,covered,FI,literal,decode_pattern

def exact(name):
    return "    template IN A "+name+" {\n        match ^"+name.replace(".","[.]")+"[.]$\n        answer \"{{ .Name }} 20 IN A 89.125.90.101\"\n    }\n"
def family(names):
    return "    template IN A . {\n        match (?i)^(?:[a-z0-9-]+[.])*(?:"+"|".join(n.replace(".","[.]") for n in names)+")[.]$\n        answer \"{{ .Name }} 20 IN A 89.125.90.101\"\n    }\n"
def source():
    return "tls://.:853 {\n"+"".join(exact("host"+str(i)+".example.net") for i in range(300))+family(["family"+str(i)+".example.net" for i in range(75)])+"}\n"

class SharedRouteTests(unittest.TestCase):
    def test_derivation(self):
        p=parse(source())
        self.assertEqual(len(p["exact"]),300)
        self.assertEqual(len(p["families"]),75)
        self.assertTrue(covered(p,"host299.example.net"))
        self.assertTrue(covered(p,"a.b.family74.example.net"))
        self.assertFalse(covered(p,"notfamily74.example.net"))
        core=render_core(p,"tls://.:8853 {\n  bind 127.0.0.1\n  forward . tls://1.1.1.1 tls://1.0.0.1 {\n  }\n}\n")
        self.assertIn(FI,core)
        self.assertIn("tls://.:18855 {",core)
        for kind in ("A","AAAA","CNAME","HTTPS","SVCB"):self.assertEqual(core.count("template IN "+kind+" . {"),1)
        nginx=render_nginx(p)
        self.assertIn("listen 127.0.0.1:14443;",nginx)
        self.assertIn('default "";',nginx)
        self.assertNotIn("0.0.0.0:443",nginx)
    def test_reject_unknown_semantics(self):
        for bad in (source().replace("89.125.90.101",FI,1),source().replace("(?i)^(?:[a-z0-9-]+[.])*","(?i)^.*",1),source()+"\nimport unknown\n"):
            with self.assertRaises(ValueError):parse(bad)
        for pattern in ("^abc.example[.]net[.]$","^.*[.]example[.]net[.]$","^mnebyvpn[.]site[.]$"):
            with self.assertRaises(ValueError):literal(pattern)
        self.assertEqual(literal(r"^api\.example\.net\.$"),"api.example.net")

    def test_existing_mixed_renderer(self):
        import importlib.util
        path=Path(__file__).resolve().parents[2]/"scripts/mnebydns-meta-foreign-family-render-20261112.py"
        spec=importlib.util.spec_from_file_location("meta_renderer",path)
        mod=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        pattern,_=mod.patterns()
        names,roots=decode_pattern(pattern)
        self.assertEqual(names,set(mod.META_EXACT))
        self.assertEqual(roots,set(mod.META_SUFFIXES))
        for name in names|roots:
            self.assertTrue(mod.belongs_to_meta(name))
        p=parse(source()[:-2]+'    template IN A . {\n        match '+pattern+'\n        answer "{{ .Name }} 20 IN A 89.125.90.101"\n    }\n}\n')
        self.assertEqual(len(p["exact"]),303)
        self.assertEqual(len(p["families"]),92)
        self.assertTrue(covered(p,"video.cdninstagram.com"))
        self.assertFalse(covered(p,"unrelated.akamaihd.net"))
    def test_grouped_literals(self):
        for pattern in (r"(?i)^(?:api\.example\.net|www\.example\.net)\.$",r"^(api[.]example[.]net|www[.]example[.]net)[.]$"):
            self.assertEqual(decode_pattern(pattern),({"api.example.net","www.example.net"},set()))
        self.assertEqual(decode_pattern('"^api[.]example[.]net[.]$"'),({"api.example.net"},set()))
        for pattern in (r"(?i)^(?:.*|api\.example\.net)\.$",r"^api.example[.]net[.]$",r"(?i)^(?:[a-z0-9-]+[.])*(?:api[.]example[.]net|.*)[.]$"):
            with self.assertRaises(ValueError):decode_pattern(pattern)

    def test_single_family_and_capturing_groups(self):
        for pattern in (
            r"(?i)^(?:[a-z0-9-]+[.])*googlevideo[.]com[.]$",
            r"(?i)^([a-z0-9-]+[.])*googlevideo[.]com[.]$",
            r"(?i)^(?:[0-9a-z-]{1,63}\.)*googlevideo\.com\.$",
            r"(?i)^((?:[a-z0-9-]+[.])*)(googlevideo[.]com)[.]$",
        ):
            self.assertEqual(decode_pattern(pattern),(set(),{"googlevideo.com"}))
        self.assertEqual(decode_pattern(r"(?i)^(?:api[.]example[.](?:net|com))[.]$"),({"api.example.net","api.example.com"},set()))
        self.assertEqual(decode_pattern(r"(?i)^(?:api[.]example[.]net|(?:[a-z0-9-]+[.])*video[.]example[.]net)[.]$"),({"api.example.net"},{"video.example.net"}))
    def test_semantic_parser_rejects_widening(self):
        for pattern in (
            r"(?i)^.*example[.]net[.]$",
            r"(?i)^(?:[a-z0-9-]+[.])?example[.]net[.]$",
            r"(?i)^(?:[a-z]+[.])*example[.]net[.]$",
            r"(?i)^api[.]example[.]net[.]$(?=x)",
            r"(?i)^api[.]example[.]net[.]$|^.*$",
            r"(?i)^api[.]example[.]net[.]$|^foo[.]example[.]net[.]$",
            r"(?i)^(?:[a-z0-9-]+[.])*mnebyvpn[.]site[.]$",
            r"(?i)^(?:[a-z0-9-]+[.])*api[.](?:[a-z0-9-]+[.])*example[.]net[.]$",
            r"(?i)^api[.]example[.](?s:net)[.]$",
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaises(ValueError):decode_pattern(pattern)

    def test_live_size_regex_budget_and_parity(self):
        import re
        p={"exact":["service"+str(i)+".long-domain-name.example.net" for i in range(618)],
           "families":["family"+str(i)+".long-domain-name.example.net" for i in range(75)]}
        core=render_core(p,"tls://.:8853 {\n  bind 127.0.0.1\n  forward . tls://1.1.1.1 tls://1.0.0.1 {\n  }\n}\n")
        rules=[line.strip()[6:] for line in core.splitlines() if line.strip().startswith("match ")]
        self.assertTrue(all(len(x.encode())<=8000 for x in rules))
        self.assertGreater(len(rules),10)
        patterns=list(map(re.compile,rules))
        for name in p["exact"]+p["families"]+["a.b."+name for name in p["families"]]:
            self.assertTrue(any(x.fullmatch(name+".") for x in patterns),name)
        for name in ("example.org","not"+p["families"][0],p["exact"][0]+".evil.net"):
            self.assertFalse(any(x.fullmatch(name+".") for x in patterns),name)
