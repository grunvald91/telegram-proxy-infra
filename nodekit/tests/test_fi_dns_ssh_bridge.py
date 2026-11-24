import asyncio
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_dns_ssh_client import Channel,MeterPool,ssh_args
from fi_dns_ssh_bridge import PING_OP,PONG,SNAPSHOT_OP

# Execute actual forced bridge framing over subprocess pipes, but stub
# its two root-only dependencies. No production network or private keys.
FIXTURE=("import sys;sys.path.insert(0,sys.argv[1]);"
         "import fi_dns_ssh_bridge as b;"
         "b.meter=lambda data:data;"
         "b.snapshot=lambda:b'x'*600000;"
         "b.serve()")


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    def args(self):
        return [sys.executable,"-c",FIXTURE,str(Path(__file__).resolve().parents[1])]

    async def test_persistent_frames_and_snapshot_bound(self):
        channel=Channel(self.args())
        try:
            self.assertEqual(await channel.exchange(PING_OP),PONG)
            pid=channel.process.pid
            self.assertEqual(await channel.exchange(b'{"version":1}'),b'{"version":1}')
            self.assertEqual(await channel.exchange(SNAPSHOT_OP),b'x'*600000)
            self.assertEqual(channel.process.pid,pid)
        finally:await channel.close()

    async def test_pool_concurrent_bounded_channels(self):
        pool=MeterPool(self.args(),count=2)
        try:
            await pool.warm()
            pids=[c.process.pid for c in pool.channels]
            data=[('{"i":%d}'%n).encode() for n in range(12)]
            self.assertEqual(await asyncio.gather(*(pool(v) for v in data)),data)
            self.assertEqual([c.process.pid for c in pool.channels],pids)
            self.assertEqual(len(await pool.snapshot()),600000)
        finally:await pool.close()

    async def test_timeout_discards_process(self):
        channel=Channel([sys.executable,"-c","import time;time.sleep(10)"])
        try:
            with self.assertRaises(TimeoutError):
                await channel.exchange(PING_OP,timeout=.1)
            self.assertIsNone(channel.process)
        finally:await channel.close()

    async def test_oversized_response_rejected(self):
        fixture="import sys,struct;sys.stdin.buffer.read(1);sys.stdout.buffer.write(struct.pack('!I',4097));sys.stdout.flush()"
        channel=Channel([sys.executable,"-c",fixture])
        try:
            with self.assertRaises(ValueError):
                await channel.exchange(PING_OP)
            self.assertIsNone(channel.process)
        finally:await channel.close()

    def test_ssh_is_pinned_and_no_forwarding(self):
        args=ssh_args(Path("/key"),Path("/hosts"))
        for option in ("StrictHostKeyChecking=yes","ClearAllForwardings=yes","IdentitiesOnly=yes","ForwardAgent=no","BatchMode=yes"):
            self.assertIn(option,args)
        self.assertEqual(args[-1],"fi-dns-rpc-v1")
        self.assertNotIn("-L",args);self.assertNotIn("-R",args)
