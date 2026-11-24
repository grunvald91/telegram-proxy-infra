"""Local endpoint for the separately restricted, pinned SSH meter tunnel.

No tunnel installation, public network address, or automatic service enable.
The remote controller still verifies Ed25519 and the client verifies its signed
reply. This transport never accepts an arbitrary host supplied by a caller.
"""
from __future__ import annotations

import asyncio
import struct

from fi_dns_meter_rpc import MAX_WIRE, MeterRpcError


class LoopbackMeterTransport:
    def __init__(self, port: int, *, timeout: float = 2.0):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise MeterRpcError("Invalid private meter tunnel port")
        if type(timeout) not in (float, int) or not 0 < timeout <= 2.5:
            raise MeterRpcError("Invalid private meter tunnel timeout")
        self.port, self.timeout = port, timeout

    async def __call__(self, wire: bytes) -> bytes:
        if not isinstance(wire, bytes) or not 1 <= len(wire) <= MAX_WIRE:
            raise MeterRpcError("Invalid meter request frame")
        writer = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", self.port, limit=MAX_WIRE + 4)
                writer.write(struct.pack("!I", len(wire)) + wire)
                await writer.drain()
                size = struct.unpack("!I", await reader.readexactly(4))[0]
                if not 1 <= size <= MAX_WIRE:
                    raise MeterRpcError("Invalid meter response frame")
                response = await reader.readexactly(size)
                if await reader.read(1):
                    raise MeterRpcError("Trailing meter response bytes")
                return response
        except (OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
            raise MeterRpcError("Private meter transport unavailable") from exc
        finally:
            if writer is not None:
                writer.close()
