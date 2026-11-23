"""FI regional wildcard certificate staging with real OpenSSL CA fixtures."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fi_regional_cert_stage as stage


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=8)


class FiRegionalCertificateTests(unittest.TestCase):
    def make_pair(self, root: Path, hostname="*.fi.dns.mnebyvpn.site") -> Path:
        ca_key, ca_cert = root/"ca.key", root/"ca.crt"
        openssl("req","-x509","-newkey","rsa:2048","-nodes",
                "-days","30","-subj","/CN=MNEBYVPN Offline Test CA",
                "-keyout",ca_key,"-out",ca_cert)
        src = root/"source"
        src.mkdir(mode=0o700)
        leaf, csr = src/"leaf.pem", src/"leaf.csr"
        openssl("req","-newkey","rsa:2048","-nodes",
                "-subj","/CN=example.invalid","-keyout",
                src/"privkey.pem","-out",csr)
        ext=root/"ext.cnf"
        ext.write_text("subjectAltName=DNS:"+hostname+
                       "\nextendedKeyUsage=serverAuth\n")
        openssl("x509","-req","-in",csr,"-CA",ca_cert,"-CAkey",ca_key,
                "-CAcreateserial","-out",leaf,"-days","21","-sha256",
                "-extfile",ext)
        (src/"fullchain.pem").write_bytes(leaf.read_bytes()+ca_cert.read_bytes())
        (src/"privkey.pem").chmod(0o600)
        (src/"fullchain.pem").chmod(0o600)
        return src

    def test_real_trusted_wildcard_and_wrong_san(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good=self.make_pair(root)
            with patch.object(stage,"CAFILE",str(root/"ca.crt")), \
                 patch.object(stage,"trusted_dir",return_value=None), \
                 patch.object(stage,"trusted_file",
                     side_effect=lambda p,size: p.read_bytes()):
                report=stage.verify_pair(good)
                self.assertTrue(report["regional_san_exact"])
                self.assertTrue(report["trusted_chain_for_two_names"])
                self.assertTrue(report["certificate_key_match"])
                bad=root/"other"
                bad.mkdir()
                (bad/"fullchain.pem").write_bytes((good/"fullchain.pem").read_bytes())
                (bad/"privkey.pem").write_bytes((good/"privkey.pem").read_bytes())
                # Even with good SAN, a substituted key is rejected.
                openssl("genpkey","-algorithm","RSA","-pkeyopt",
                        "rsa_keygen_bits:2048","-out",bad/"privkey.pem")
                with self.assertRaises(stage.CertStageError):
                    stage.verify_pair(bad)

    def test_certificate_stage_never_authorizes_unknown_fi(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"fi-test-01"
            root.mkdir(mode=0o700)
            source=Path(tmp)/"source"
            source.mkdir(mode=0o700)
            with patch.object(stage,"ROOT",root), \
                 patch.object(stage,"DEST",root/"fi-regional-tls"), \
                 patch.object(stage.os,"geteuid",return_value=0):
                # No approved manifest: cannot write a certificate.
                with self.assertRaises((ValueError,OSError)):
                    stage.stage(source)
                self.assertFalse((root/"fi-regional-tls").exists())

    def test_symlink_and_world_readable_files_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            cert=d/"fullchain.pem"
            cert.write_text("fake")
            cert.chmod(0o644)
            with self.assertRaises(stage.CertStageError):
                stage.trusted_file(cert,100)
            cert.chmod(0o600)
            symlink=d/"alias.pem"
            symlink.symlink_to(cert)
            with self.assertRaises(stage.CertStageError):
                stage.trusted_file(symlink,100)


if __name__ == "__main__":
    unittest.main()
