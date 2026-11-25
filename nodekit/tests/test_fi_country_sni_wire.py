"""Exercise the exact deployed probe against real generated TLS bindings."""
import contextlib
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from fi_country_stage import deny_old_name, OLD_NAME
from fi_dns_tls_session import SniBindings

@contextlib.contextmanager
def endpoint(handler):
    errors=[]
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1",0));server.listen(1);server.settimeout(6)
        def serve():
            try:
                with server.accept()[0] as conn:
                    conn.settimeout(5);handler(conn)
            except BaseException as exc:errors.append(exc)
        worker=threading.Thread(target=serve,daemon=True);worker.start()
        try:yield server.getsockname()[1]
        finally:
            worker.join(7)
            if worker.is_alive():raise AssertionError("test server hung")
            if errors:raise errors[0]

class Probe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cert=Path(cls.tmp.name)/"cert.pem";key=Path(cls.tmp.name)/"key.pem"
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                        "-subj","/CN=*.fi.mnebyvpn.site","-addext","subjectAltName=DNS:*.fi.mnebyvpn.site",
                        "-keyout",str(key),"-out",str(cert)],check=True,capture_output=True)
        cls.cert=cert;cls.key=key
    def test_real_binding(self):
        binding=SniBindings(self.cert,self.key)
        def reject(conn):
            try:
                with binding.context.wrap_socket(conn,server_side=True):raise AssertionError("old SNI accepted")
            except ssl.SSLError as exc:
                if exc.reason!="CALLBACK_FAILED":raise
        with endpoint(reject) as port:deny_old_name(port)
        # Prove the very same binding can negotiate a valid new-country SNI.
        def accept(conn):
            with binding.context.wrap_socket(conn,server_side=True) as tls:
                tls.sendall(b"ok")
        with endpoint(accept) as port:
            ctx=ssl.create_default_context(cafile=str(self.cert))
            with socket.create_connection(("127.0.0.1",port),timeout=5) as conn:
                with ctx.wrap_socket(conn,server_hostname="aaaaaaaaaaaa.fi.mnebyvpn.site") as tls:
                    self.assertEqual(tls.recv(2),b"ok")
    def test_wrong_response_rejected(self):
        for wire in (b"",b"\x15\x03\x03\x00\x02\x02\x50",
                     b"\x15\x03\x03\x00\x02\x01\x70",
                     b"\x16\x03\x03\x00\x02\x02\x70",
                     b"\x15\x03\x03\x00\x02\x02"):
            with self.subTest(wire=wire):
                def send(conn):
                    conn.recv(65536)
                    if wire:conn.sendall(wire)
                with endpoint(send) as port:
                    with self.assertRaises((RuntimeError,OSError)):deny_old_name(port)
    def test_permissive_tls_rejected(self):
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert,self.key)
        def permissive(conn):
            try:
                with ctx.wrap_socket(conn,server_side=True):pass
            except (ssl.SSLError,OSError):pass
        with endpoint(permissive) as port:
            with self.assertRaisesRegex(RuntimeError,"old_sni_not_explicit_alert"):deny_old_name(port)

if __name__=="__main__":unittest.main()
