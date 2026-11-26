import asyncio
import unittest
import fi_public_https_relay as relay

class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_duplex_and_half_close(self):
        async def echo(reader, writer):
            try:
                body = await reader.read()
                writer.write(body[::-1])
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        backend = await asyncio.start_server(echo, "127.0.0.1", 0)
        before = relay.BACKEND
        relay.BACKEND = backend.sockets[0].getsockname()
        instance = relay.Relay()
        frontend = await asyncio.start_server(instance.handle, "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(*frontend.sockets[0].getsockname())
            writer.write(b"123456789")
            await writer.drain()
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"987654321")
            writer.close()
            await writer.wait_closed()
            for _ in range(20):
                if instance.active == 0: break
                await asyncio.sleep(.02)
            self.assertEqual(instance.active, 0)
            self.assertFalse(instance.ips)
        finally:
            frontend.close()
            backend.close()
            await frontend.wait_closed()
            await backend.wait_closed()
            relay.BACKEND = before

if __name__ == "__main__":
    unittest.main()
