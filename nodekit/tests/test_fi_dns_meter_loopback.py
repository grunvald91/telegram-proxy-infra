import asyncio
import struct
import unittest
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_dns_meter_loopback import LoopbackMeterTransport
from fi_dns_meter_rpc import MeterRpcError


class MeterTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_loopback_frame_and_rejections(self):
        async def exchange(response, expect=True):
            async def handle(reader,writer):
                try:
                    size=struct.unpack("!I",await reader.readexactly(4))[0]
                    payload=await reader.readexactly(size)
                    self.assertEqual(payload,b'{"version":1}')
                    writer.write(response)
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
            server=await asyncio.start_server(handle,"127.0.0.1",0)
            try:
                transport=LoopbackMeterTransport(server.sockets[0].getsockname()[1])
                if expect:
                    self.assertEqual(await transport(b'{"version":1}'),b"ok")
                else:
                    with self.assertRaises(MeterRpcError):
                        await transport(b'{"version":1}')
            finally:
                server.close()
                await server.wait_closed()
        await exchange(struct.pack("!I",2)+b"ok")
        await exchange(struct.pack("!I",4097),False)
        await exchange(struct.pack("!I",3)+b"ok",False)
        await exchange(struct.pack("!I",2)+b"okx",False)

    async def test_transport_rejects_invalid_local_port_and_request(self):
        for port in (0,53,True,65536):
            with self.assertRaises(MeterRpcError):
                LoopbackMeterTransport(port)
        with self.assertRaises(MeterRpcError):
            await LoopbackMeterTransport(12345)(b"x"*4097)
