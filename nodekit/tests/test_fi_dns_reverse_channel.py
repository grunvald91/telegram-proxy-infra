import asyncio
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_dns_reverse_channel import ReverseTransport,ssh_args,COMMAND
from fi_dns_ssh_bridge import PING_OP,PONG,SNAPSHOT_OP

class ReverseTests(unittest.IsolatedAsyncioTestCase):
    def test_pinned_ssh(self):
        args=ssh_args()
        self.assertIn("StrictHostKeyChecking=yes",args)
        self.assertIn("ClearAllForwardings=yes",args)
        self.assertIn("HostKeyAlias=fi.mnebyvpn.site",args)
        self.assertEqual(args[-1],COMMAND)
        self.assertNotIn("-R",args);self.assertNotIn("-L",args)

    @unittest.skipUnless(os.geteuid()==0,"root-only Unix peer contract")
    async def test_real_stdio_and_unix_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"channel.sock"
            a,b=os.pipe();c,d=os.pipe()
            lib=str(Path(__file__).resolve().parents[1])
            fi=ru=None
            try:
                fi=subprocess.Popen([sys.executable,"-c","import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from fi_dns_reverse_channel import fi_serve;fi_serve(Path(sys.argv[2]))",lib,str(path)],stdin=a,stdout=d,stderr=subprocess.DEVNULL)
                ru=subprocess.Popen([sys.executable,"-c","import sys;sys.path.insert(0,sys.argv[1]);import fi_dns_ssh_bridge as b;b.meter=lambda data:data;b.snapshot=lambda:b'x'*600000;b.serve()",lib],stdin=c,stdout=b,stderr=subprocess.DEVNULL)
                for fd in (a,b,c,d):os.close(fd)
                a=b=c=d=-1
                for _ in range(40):
                    if path.is_socket():break
                    await asyncio.sleep(.05)
                self.assertTrue(path.is_socket())
                transport=ReverseTransport(path)
                self.assertEqual(await transport.exchange(PING_OP),PONG)
                self.assertEqual(await transport(b'{"version":1}'),b'{"version":1}')
                self.assertEqual(await transport.snapshot(),b'x'*600000)
                self.assertEqual(await transport.exchange(PING_OP),PONG)
            finally:
                for fd in (a,b,c,d):
                    if fd>=0:os.close(fd)
                for p in (fi,ru):
                    if p is not None:
                        if p.poll() is None:p.terminate()
                        p.wait(timeout=5)
