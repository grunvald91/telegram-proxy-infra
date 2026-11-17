#!/usr/bin/env python3
"""Verified TLS/HTTP controls to DE89, including a valid large fragmented hello."""
import json, socket, ssl, time
HOST="rr1---sn-gxuo03g-ig3s.googlevideo.com"
def hello(tls12=False,padding=0):
    ctx=ssl.create_default_context()
    if tls12:ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2
    alpn=["http/1.1"]
    while padding:
        n=min(padding,250);alpn.append("z"*n);padding-=n
    ctx.set_alpn_protocols(alpn)
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    tls=ctx.wrap_bio(incoming,outgoing,server_side=False,server_hostname=HOST)
    try:tls.do_handshake()
    except ssl.SSLWantReadError:pass
    return tls,incoming,outgoing,outgoing.read()
def control(label,tls12=False,large=False,split=False):
    start=time.monotonic();result={"label":label,"destination":"DE89","sni":HOST}
    try:
        tls,inc,out,initial=hello(tls12)
        if large:
            lo,hi=0,2000
            while lo<hi:
                mid=(lo+hi)//2
                candidate=hello(tls12,mid)
                if len(candidate[3])<1592:lo=mid+1
                else:hi=mid
            tls,inc,out,initial=hello(tls12,lo)
        result['clienthello_record_bytes']=len(initial)
        with socket.create_connection(("89.125.90.101",443),timeout=8) as sock:
            sock.settimeout(8)
            if split:
                sock.sendall(initial[:1448]);time.sleep(.25);sock.sendall(initial[1448:])
            else:sock.sendall(initial)
            while True:
                try:tls.do_handshake();break
                except ssl.SSLWantReadError:
                    pending=out.read()
                    if pending:sock.sendall(pending)
                    data=sock.recv(65536)
                    if not data:raise EOFError('TLS_EOF')
                    inc.write(data)
            pending=out.read()
            if pending:sock.sendall(pending)
            result['tls']=tls.version();result['certificate_verified']=True
            tls.write(('GET / HTTP/1.1\r\nHost: '+HOST+'\r\nConnection: close\r\n\r\n').encode())
            pending=out.read()
            if pending:sock.sendall(pending)
            while True:
                try:
                    response=tls.read(100);break
                except ssl.SSLWantReadError:
                    pending=out.read()
                    if pending:sock.sendall(pending)
                    data=sock.recv(65536)
                    if not data:raise EOFError('HTTP_EOF')
                    inc.write(data)
            result['http_status_line']=response.split(b'\r\n')[0].decode('ascii','replace')
    except Exception as e:result['error']=type(e).__name__
    result['elapsed_ms']=round((time.monotonic()-start)*1000)
    print('CONTROL='+json.dumps(result,sort_keys=True),flush=True)
    return 'error' not in result
if __name__=='__main__':
    results=[control('baseline'),control('large_1592',large=True),
             control('large_split_1448_then_tail',large=True,split=True),control('TLS12',tls12=True)]
    print('CONTROLS_ALL_PASSED='+str(all(results)).lower(),flush=True)
    if not all(results):raise SystemExit(1)
