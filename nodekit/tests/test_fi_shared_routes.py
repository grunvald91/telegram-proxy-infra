import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_shared_routes import parse,render_core,render_nginx,covered,FI,literal

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
        for kind in ("A","AAAA","CNAME","HTTPS","SVCB"):self.assertEqual(core.count("template IN "+kind+" . {"),2)
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
