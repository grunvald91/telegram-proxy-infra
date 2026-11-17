import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "install_components.py"
spec = importlib.util.spec_from_file_location("nodekit_components", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


class TestComponents(unittest.TestCase):
    def test_all_official_assets_have_pinned_sha_and_https(self):
        for arch, assets in m.ASSETS.items():
            self.assertEqual(set(assets), {"xray", "coredns"})
            for name, (url, checksum, kind, path) in assets.items():
                with self.subTest(arch=arch, name=name):
                    self.assertTrue(url.startswith("https://github.com/"))
                    self.assertRegex(checksum, r"^[0-9a-f]{64}$")
                    self.assertIn(kind, ("zip", "tgz"))
                    self.assertTrue(path.startswith("/opt/"))

    def test_refuse_unpinned_url_and_bad_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "download"
            with self.assertRaises(m.InstallError):
                m.download("http://untrusted.example/file", "0"*64, target)
            data = b"A" * 11000
            class Stream(io.BytesIO):
                def __enter__(self): return self
                def __exit__(self, *args): self.close()
            with self.assertRaises(m.InstallError):
                m.download("https://github.com/example/test", "0"*64, target,
                           opener=lambda *a, **kw: Stream(data))
            self.assertFalse(target.exists())

    def test_valid_zip_archive_single_member_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, output = Path(tmp) / "x.zip", Path(tmp) / "xray"
            raw = b"X" * 12000
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("xray", raw)
                z.writestr("../../etc/shadow", b"malicious")
            checksum = m.unpack(archive, "zip", "xray", output)
            self.assertEqual(checksum, hashlib.sha256(raw).hexdigest())
            self.assertEqual(output.read_bytes(), raw)
            self.assertFalse((Path(tmp) / "etc").exists())

    def test_targz_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, output = Path(tmp) / "c.tgz", Path(tmp) / "coredns"
            with tarfile.open(archive, "w:gz") as t:
                info = tarfile.TarInfo("coredns")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
            with self.assertRaises(m.InstallError):
                m.unpack(archive, "tgz", "coredns", output)

    def test_targz_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, output = Path(tmp) / "c.tgz", Path(tmp) / "coredns"
            content = b"C" * 11000
            with tarfile.open(archive, "w:gz") as t:
                info = tarfile.TarInfo("coredns")
                info.size = len(content)
                t.addfile(info, io.BytesIO(content))
            self.assertEqual(m.unpack(archive, "tgz", "coredns", output),
                             hashlib.sha256(content).hexdigest())

    def test_existing_executable_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = b"nodekit-test"
            source = Path(tmp) / "source"
            source.write_bytes(raw)
            destination = Path(tmp) / "bins" / "xray"
            with patch.object(m, "safe_dir", return_value=None):
                m.install_binary(source, destination, hashlib.sha256(raw).hexdigest())
                self.assertEqual(destination.read_bytes(), raw)
                with self.assertRaises(m.InstallError):
                    m.install_binary(source, destination, "0"*64)
                self.assertEqual(destination.read_bytes(), raw)

    def test_apt_denies_service_starts_and_cleans_policy(self):
        commands = []
        def runner(command, **kw):
            commands.append(command)
            if command[:2] == ["systemctl", "is-active"]:
                return Result(returncode=3)
            if command[:2] == ["systemctl", "is-enabled"]:
                return Result(returncode=1)
            if command[0] == "dpkg-query":
                return Result(stdout="1.2.3")
            return Result()
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / "policy-rc.d"
            versions = m.install_apt(runner=runner, policy=policy)
            self.assertEqual(set(versions), set(m.PACKAGES))
            self.assertFalse(policy.exists())
            self.assertTrue(any(x[:2] == ["systemctl", "disable"] for x in commands))
            self.assertTrue(any(x[:2] == ["apt-get", "install"] for x in commands))
            policy.write_text("operator configured")
            with self.assertRaises(FileExistsError):
                m.install_apt(runner=runner, policy=policy)
            self.assertEqual(policy.read_text(), "operator configured")

    def test_existing_manifest_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = Path(tmp) / "fi-test-01"
            node.mkdir()
            (node / "components-manifest.json").write_text('{"node_id": "wrong"}')
            with patch.object(m, "nginx_must_be_inactive", return_value=None):
                with patch.object(m, "safe_manifest", return_value={"node_id": "wrong"}):
                    with self.assertRaises(m.InstallError):
                        m.stage(node)


if __name__ == "__main__":
    unittest.main()
