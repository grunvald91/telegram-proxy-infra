#!/usr/bin/env python3
"""Validate native QUIC+HTTP/3 to real Threads origin with certificate checks.
No proxy changes, no client data, no bypass of TLS trust validation.
"""
import asyncio
import ssl

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration

class Head(QuicConnectionProtocol):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw)
        self.h3=H3Connection(self._quic)
        self.responses={}
    def quic_event_received(self,event):
        super().quic_event_received(event)
        for h in self.h3.handle_event(event):
            if isinstance(h,(HeadersReceived,DataReceived)):
                f=self.responses.get(h.stream_id)
                if not f or f.done():continue
                if isinstance(h,HeadersReceived):
                    code=next((v.decode() for k,v in h.headers if k==b':status'),None)
                    if code:f.set_result(code)
    async def head(self,host):
        id=self._quic.get_next_available_stream_id()
        future=asyncio.get_running_loop().create_future()
        self.responses[id]=future
        self.h3.send_headers(stream_id=id,headers=[
            (b':method',b'HEAD'), (b':scheme',b'https'),
            (b':authority',host.encode()),(b':path',b'/'),
            (b'user-agent',b'MNEBYDNS-QUIC-Test/1.0'),
        ],end_stream=True)
        self.transmit()
        return await asyncio.wait_for(future,8)

async def run(host):
    conf=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,
                           server_name=host,verify_mode=ssl.CERT_REQUIRED)
    try:
        async with connect(host,443,configuration=conf,
                           create_protocol=Head,wait_connected=True) as proto:
            print('h3_'+host+'_QUIC_TLS_verified=true',flush=True)
            try:
                status=await proto.head(host)
                print('h3_'+host+'_HEAD_status='+str(status),flush=True)
                print('h3_'+host+'_HTTP3_response=true',flush=True)
            except Exception as e:
                print('h3_'+host+'_HEAD_error='+type(e).__name__,flush=True)
    except Exception as e:
        print('h3_'+host+'_QUIC_TLS_verified=false',flush=True)
        print('h3_'+host+'_error='+type(e).__name__,flush=True)

async def main():
    await run('www.threads.com')
    await run('threads.com')
    await run('graph.threads.com')

if __name__=='__main__':asyncio.run(main())
