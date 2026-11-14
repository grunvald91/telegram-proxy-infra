#!/usr/bin/env python3
"""Strict TLS HTTP/3 probe of real YouTube origin via the local RU UDP relay.
No DNS rewrites, credentials, application data capture, or service mutations.
"""
import asyncio
import os
import ssl
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN,H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

class Probe(QuicConnectionProtocol):
    def __init__(self,*a,**kwargs):
        super().__init__(*a,**kwargs)
        self.h3=H3Connection(self._quic)
        self.pending={}
    def quic_event_received(self,event):
        super().quic_event_received(event)
        for item in self.h3.handle_event(event):
            if isinstance(item,(HeadersReceived,DataReceived)):
                future=self.pending.get(item.stream_id)
                if future is None or future.done():continue
                if isinstance(item,HeadersReceived):
                    code=next((v.decode('ascii') for k,v in item.headers if k==b':status'),None)
                    if code and code.isdigit():future.set_result(int(code))
    async def head(self,host):
        stream=self._quic.get_next_available_stream_id()
        future=asyncio.get_running_loop().create_future()
        self.pending[stream]=future
        self.h3.send_headers(stream_id=stream,headers=[
            (b':method',b'HEAD'),(b':scheme',b'https'),(b':authority',host.encode('ascii')),
            (b':path',b'/'),(b'user-agent',b'MNEBYDNS-QUIC-Synthetic/1.0')
        ],end_stream=True)
        self.transmit()
        return await asyncio.wait_for(future,10)

async def once(host):
    conf=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,
                           server_name=host,verify_mode=ssl.CERT_REQUIRED)
    via=os.environ.get('YOUTUBE_QUIC_VIA','127.0.0.1')
    try:
        async with connect(via,443,configuration=conf,create_protocol=Probe,
                           wait_connected=True) as proto:
            print('YOUTUBE_REAL_H3_'+host+'_TLS_VERIFIED=true',flush=True)
            status=await proto.head(host)
            print('YOUTUBE_REAL_H3_'+host+'_HTTP_STATUS='+str(status),flush=True)
            return 100<=status<=599
    except Exception as error:
        print('YOUTUBE_REAL_H3_'+host+'_ERROR='+type(error).__name__,flush=True)
        return False

async def main():
    ok=await asyncio.wait_for(once('www.youtube.com'),35)
    if not ok:raise SystemExit('YOUTUBE_HTTP3_REAL_ORIGIN_NOT_VERIFIED')
    print('YOUTUBE_HTTP3_RU_WG_DE_CERT_AND_HTTP=PASS',flush=True)

if __name__=='__main__':
    asyncio.run(main())
