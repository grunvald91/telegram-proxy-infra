#!/usr/bin/env python3
"""Bounded, certificate-verified HTTP/3 origin and isolated UDP relay comparison."""
import asyncio, importlib.util, ipaddress, json, pathlib, socket, ssl, sys, urllib.parse
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived

class Probe(QuicConnectionProtocol):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw); self.h3=H3Connection(self._quic); self.pending={}
    def quic_event_received(self,event):
        super().quic_event_received(event)
        for item in self.h3.handle_event(event):
            if not isinstance(item,(HeadersReceived,DataReceived)):continue
            p=self.pending.get(item.stream_id)
            if not p or p['future'].done():continue
            if isinstance(item,HeadersReceived):
                headers=dict(item.headers); p['status']=int(headers.get(b':status',b'0'))
                p['mime']=headers.get(b'content-type',b'').decode('ascii','replace')[:100]
            else:
                p['bytes']+=len(item.data)
            if p['bytes']>=65536 or item.stream_ended or (not p['media'] and p['status']):
                p['future'].set_result({k:v for k,v in p.items() if k not in ('future','media')})
                if p['bytes']>=65536 and not item.stream_ended:
                    self._quic.stop_stream(item.stream_id,0);self.transmit()
    async def request(self,url,media):
        u=urllib.parse.urlsplit(url); stream=self._quic.get_next_available_stream_id()
        f=asyncio.get_running_loop().create_future()
        self.pending[stream]={'future':f,'media':media,'status':0,'bytes':0,'mime':''}
        path=u.path or '/'
        if u.query:path+='?'+u.query
        h=[(b':method',b'GET' if media else b'HEAD'),(b':scheme',b'https'),(b':authority',u.hostname.encode()),(b':path',path.encode()),(b'user-agent',b'MNEBYDNS-H3-Route-Diagnostic/1.0')]
        if media:h.append((b'range',b'bytes=0-65535'))
        self.h3.send_headers(stream_id=stream,headers=h,end_stream=True);self.transmit()
        return await asyncio.wait_for(f,7)

async def probe(target,via=None):
    from aioquic.quic.configuration import QuicConfiguration
    host=urllib.parse.urlsplit(target['url']).hostname
    conf=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,server_name=host,verify_mode=ssl.CERT_REQUIRED)
    async def run():
        if via:ip,port=via
        else:
            ips=await asyncio.to_thread(socket.getaddrinfo,host,443,socket.AF_INET,socket.SOCK_DGRAM)
            ip=next(x[4][0] for x in ips if ipaddress.ip_address(x[4][0]).is_global and x[4][0]!='89.125.90.101');port=443
        async with connect(ip,port,configuration=conf,create_protocol=Probe) as p:
            r=await p.request(target['url'],target.get('media',False));r['tls_verified']=True;return r
    try:r=await asyncio.wait_for(run(),12)
    except Exception as e:r={'error':type(e).__name__,'tls_and_http_verified':False}
    r.update(label=target['label'],route=('DE89_public_relay' if via==('89.125.90.101',443) else 'isolated_relay') if via else 'DE89_origin')
    print('H3_ROUTE_RESULT='+json.dumps(r,sort_keys=True),flush=True)
    return r

async def main():
    targets=json.loads(sys.stdin.read()); assert len(targets)<=5
    for t in targets:
        u=urllib.parse.urlsplit(t['url'])
        assert u.scheme=='https' and (u.hostname in ('www.youtube.com','youtubei.googleapis.com') or u.hostname.endswith('.googlevideo.com'))
    direct=await asyncio.gather(*(probe(t) for t in targets))
    spec=importlib.util.spec_from_file_location('isolated_quic',pathlib.Path(__file__).with_name('relay.py'))
    mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
    transport,router=await asyncio.get_running_loop().create_datagram_endpoint(lambda:mod.YoutubeRouter('de-public','','127.0.0.1'),local_addr=('127.0.0.1',19445))
    try:relay=await asyncio.gather(*(probe(t,('127.0.0.1',19445)) for t in targets))
    finally:transport.close()
    print('ISOLATED_RELAY_COUNTERS='+json.dumps(router.counters,sort_keys=True),flush=True)
    media_ok=lambda rows:any(r.get('label')=='media' and r.get('status')==206 and r.get('bytes',0)>=65536 and r.get('mime','').startswith(('video/','audio/')) and r.get('tls_verified') for r in rows)
    print('H3_ACTUAL_MEDIA_DIRECT_AND_RELAY='+json.dumps(media_ok(direct) and media_ok(relay)),flush=True)

if __name__=='__main__':asyncio.run(main())
