import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import telemt_stage as m

class TelemtTests(unittest.TestCase):
    def test_closed_config(self):
        cfg = m.config("fi.mnebyvpn.site").decode()
        self.assertIn('enabled = false', cfg)
        self.assertIn('ip = "127.0.0.1"', cfg)
        self.assertIn('[access.users]\n', cfg)
        self.assertNotIn("0.0.0.0", cfg)
        with self.assertRaises(m.TelemtError):
            m.config('unsafe";\n[access.users]\nkey = "secret')

    def test_unpinned_archive_rejected(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            blob = b"\x7fELFtest"
            entry = tarfile.TarInfo("telemt")
            entry.size = len(blob)
            tar.addfile(entry, io.BytesIO(blob))
        with self.assertRaises(m.TelemtError):
            m.extract_binary(stream.getvalue(), "x86_64")

    def test_idempotent_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp)/"fi-test-01"
            node.mkdir()
            with patch.object(m, "download", return_value=b"\x7fELFfixture"), \
                 patch.object(m, "safe_dir"), \
                 patch.object(m, "safe_manifest", side_effect=lambda p: json.loads(p.read_text())), \
                 patch.object(m, "check_file", side_effect=lambda p, h, mx:
                    p.read_bytes() if hashlib.sha256(p.read_bytes()).hexdigest()==h
                    else (_ for _ in ()).throw(m.TelemtError("changed"))):
                a = m.stage(node,"fi.mnebyvpn.site")
                self.assertFalse(a["users_enabled"])
                self.assertEqual(a,m.stage(node,"fi.mnebyvpn.site"))
                (node/"telemt-stage"/"config.toml").write_text("unsafe")
                with self.assertRaises(m.TelemtError):
                    m.inspect(node,"fi.mnebyvpn.site")

if __name__=="__main__":
    unittest.main()
