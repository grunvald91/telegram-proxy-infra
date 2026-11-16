"""Unit tests for safe DE stable checkpoint promotion helper."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import meta_de_sync_google_checkpoint as m


VALID_GOOGLE_BLOCK = (
    "\n# Verified Google RU ingress 20261116\n"
    + " ".join(f"tls://{h}:853" for h in m.GOOGLE_HOSTS)
    + " {\n"
    "    bind 89.125.90.101\n"
    "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n"
    "    template IN A {\n"
    '        answer "{{ .Name }} 20 IN A 188.120.254.223"\n'
    "    }\n"
    "    template IN AAAA { rcode NOERROR }\n"
    "    template IN HTTPS { rcode NOERROR }\n"
    "    template IN SVCB { rcode NOERROR }\n"
    "    forward . tls://9.9.9.9 { tls_servername dns.quad9.net }\n"
    "    errors\n"
    "}\n"
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SyncGoogleCheckpointTests(unittest.TestCase):
    def _setup_tree(self, root: Path, *, with_proxy: bool = True, with_backup: bool = True):
        cp_base = root / "opt/mnebydns-stable-checkpoints"
        old_dir = cp_base / "1700000000"
        old_dir.mkdir(parents=True)

        old_dns = b".:853 {\n  bind 89.125.90.101\n}\n"
        old_nginx = b"stream { server { listen 89.125.90.101:443; } }\n"
        old_proxy = b"server { listen 127.0.0.1:8080; }\n"

        (old_dir / "dns.stable").write_bytes(old_dns)
        (old_dir / "nginx.stable").write_bytes(old_nginx)
        manifest = [
            f"{_sha(old_nginx)}  nginx.stable\n",
            f"{_sha(old_dns)}  dns.stable\n",
        ]
        live_proxy = root / "etc/mnebydns-googlepilot/nginx.conf"
        if with_proxy:
            (old_dir / "proxy.stable").write_bytes(old_proxy)
            manifest.append(f"{_sha(old_proxy)}  proxy.stable\n")
            live_proxy.parent.mkdir(parents=True)
            live_proxy.write_bytes(old_proxy)
        (old_dir / "stable-manifest.sha256").write_text("".join(manifest), encoding="utf-8")

        pointer = cp_base / "current"
        pointer.write_text(str(old_dir) + "\n", encoding="utf-8")
        pointer.chmod(0o600)

        live_dns = root / "opt/mnebydns-dot/Corefile"
        live_dns.parent.mkdir(parents=True)
        live_dns.write_bytes(old_dns + VALID_GOOGLE_BLOCK.encode("utf-8"))

        live_nginx = root / "etc/nginx/nginx.conf"
        live_nginx.parent.mkdir(parents=True)
        live_nginx.write_bytes(old_nginx)

        backup = root / "var/backups/mnebydns-google-route-20261116-053515/Corefile"
        if with_backup:
            backup.parent.mkdir(parents=True)
            backup.write_bytes(old_dns)

        return {
            "pointer_path": pointer,
            "live_dns_path": live_dns,
            "live_nginx_path": live_nginx,
            "live_proxy_path": live_proxy,
            "backup_corefile_path": backup,
            "lock_path": root / "run/lock/test.lock",
            "de_stage_state_path": root / "var/lib/mneby-meta-v26-de",
        }

    def test_promotes_when_only_verified_google_block_appended(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kw = self._setup_tree(root)
            promoted = Path(m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1799999999))
            self.assertEqual(promoted.name, "1799999999")
            self.assertEqual(kw["pointer_path"].read_text().strip(), str(promoted))
            self.assertEqual((promoted / "dns.stable").read_bytes(), kw["live_dns_path"].read_bytes())
            self.assertEqual((promoted / "nginx.stable").read_bytes(), kw["live_nginx_path"].read_bytes())
            self.assertEqual((promoted / "proxy.stable").read_bytes(), kw["live_proxy_path"].read_bytes())
            names = m.verify_manifest(promoted)
            self.assertEqual(names, ["nginx.stable", "dns.stable", "proxy.stable"])

            # Idempotent on second call
            second = m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1800000000)
            self.assertEqual(second, str(promoted))

    def test_rejects_unexpected_corefile_edit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kw = self._setup_tree(root)
            kw["live_dns_path"].write_bytes(
                kw["live_dns_path"].read_bytes() + b"\nexample.com:853 { forward . 1.1.1.1 }\n"
            )
            before = kw["pointer_path"].read_text()
            with self.assertRaisesRegex(RuntimeError, "Verified Google RU ingress 20261116"):
                m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1799999999)
            self.assertEqual(kw["pointer_path"].read_text(), before)
            self.assertFalse((kw["pointer_path"].parent / "1799999999").exists())

    def test_rejects_nginx_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kw = self._setup_tree(root)
            kw["live_nginx_path"].write_bytes(b"changed\n")
            with self.assertRaisesRegex(RuntimeError, "nginx.conf differs"):
                m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1799999999)

    def test_rejects_proxy_drift_and_backup_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kw = self._setup_tree(root)
            kw["live_proxy_path"].write_bytes(b"changed\n")
            with self.assertRaisesRegex(RuntimeError, "proxy nginx.conf differs"):
                m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1799999999)

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kw = self._setup_tree(root)
            kw["backup_corefile_path"].write_bytes(b"different old\n")
            with self.assertRaisesRegex(RuntimeError, "backup differs"):
                m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1799999999)

    def test_rejects_active_de_experiment_state(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kw = self._setup_tree(root)
            kw["de_stage_state_path"].mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "active DE experiment"):
                m.sync_google_checkpoint(**kw, check_services=False, now_epoch=1799999999)


if __name__ == "__main__":
    unittest.main()
