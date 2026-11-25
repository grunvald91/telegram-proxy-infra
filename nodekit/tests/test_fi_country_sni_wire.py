"""Exercise the exact deployed probe against real generated TLS bindings."""
import contextlib
import asyncio
from unittest.mock import patch, call
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import os

# The generated country runtime is deliberately separate from the legacy
# modules imported by the general bootstrap unittest discovery.
if os.environ.get('FI_COUNTRY_GENERATED_TEST') != '1':
    if __name__ == '__main__':
        raise RuntimeError('generated runtime test must be launched by its dedicated CI step')
    raise unittest.SkipTest('covered by the mandatory generated country runtime CI')
from fi_country_stage import deny_old_name, verify_old_sni_denial, OLD_NAME, HOSTS
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
        for wire in (b"\x15\x03\x03\x00\x02\x02\x50",
                     b"\x15\x03\x03\x00\x02\x01\x70",
                     b"\x16\x03\x03\x00\x02\x02\x70",
                     b"\x15\x03\x03\x00\x02\x02"):
            with self.subTest(wire=wire):
                def send(conn):
                    conn.recv(65536)
                    if wire:conn.sendall(wire)
                with endpoint(send) as port:
                    with self.assertRaises((RuntimeError,OSError)):deny_old_name(port)
    def test_asyncio_binding_with_positive_controls(self):
        binding=SniBindings(self.cert,self.key)
        calls=[]
        accepted=[]
        def callback(obj,name,ctx):
            result=binding.on_sni(obj,name,ctx)
            calls.append((name,result))
            return result
        binding.context.set_servername_callback(callback)
        async def handle(reader,writer):
            accepted.append(binding.from_writer(writer))
            writer.write(b"ok")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        def valid(port):
            ctx=ssl.create_default_context(cafile=str(self.cert))
            ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2
            with socket.create_connection(("127.0.0.1",port),timeout=5) as raw:
                with ctx.wrap_socket(raw,server_hostname=HOSTS[0]) as tls:
                    self.assertEqual(tls.recv(2),b"ok")
        async def exercise():
            server=await asyncio.start_server(handle,"127.0.0.1",0,ssl=binding.context,ssl_handshake_timeout=5)
            async with server:
                port=server.sockets[0].getsockname()[1]
                await asyncio.to_thread(valid,port)
                result=await asyncio.to_thread(deny_old_name,port)
                self.assertIn(result,("PRE_HANDSHAKE_EOF","FATAL_UNRECOGNIZED_NAME"))
                await asyncio.to_thread(valid,port)
            self.assertEqual(calls,[(HOSTS[0],None),(OLD_NAME,ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME),(HOSTS[0],None)])
            self.assertEqual(accepted,[HOSTS[0],HOSTS[0]])
        asyncio.run(exercise())
    def test_eof_requires_paired_controls(self):
        with patch("fi_country_stage.deny_unknown") as control, patch("fi_country_stage.deny_old_name",return_value="PRE_HANDSHAKE_EOF") as probe:
            verify_old_sni_denial()
            self.assertEqual(control.call_args_list,[call(HOSTS[0],tls12=True),call(HOSTS[0],tls12=True)])
            probe.assert_called_once_with()
        with patch("fi_country_stage.deny_unknown",side_effect=[None,RuntimeError("positive_control_failed")]), patch("fi_country_stage.deny_old_name",return_value="PRE_HANDSHAKE_EOF"):
            with self.assertRaisesRegex(RuntimeError,"positive_control_failed"):verify_old_sni_denial()
        with patch("fi_country_stage.deny_unknown",side_effect=RuntimeError("positive_control_failed")), patch("fi_country_stage.deny_old_name") as probe:
            with self.assertRaisesRegex(RuntimeError,"positive_control_failed"):verify_old_sni_denial()
            probe.assert_not_called()
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
