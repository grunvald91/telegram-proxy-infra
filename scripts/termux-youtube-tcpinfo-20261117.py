#!/usr/bin/env python3
"""Read-only client TLS + Linux TCP_INFO; no root and no account credentials."""
import hashlib,json,os,select,socket,ssl,struct,time
def info(s):
    b=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,256)
    out={'state':b[0],'struct_bytes':len(b)}
    for name,offset,fmt in [('unacked_segments',24,'I'),('total_retransmits',100,'I'),('bytes_acked',120,'Q'),('bytes_received',128,'Q'),('bytes_sent',200,'Q'),('bytes_retransmitted',208,'Q')]:
        n=struct.calcsize('='+fmt)
        if len(b)>=offset+n:out[name]=struct.unpack_from('='+fmt,b,offset)[0]
    return out
def test(domain,tls12):
    token=os.urandom(8).hex();result={'probe':token,'domain':domain,'tls12_only':tls12}
    ctx=ssl.create_default_context();ctx.set_alpn_protocols(['mnebydns-check-'+token,'http/1.1'])
    if tls12:ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();tls=ctx.wrap_bio(incoming,outgoing,server_hostname=domain)
    try:tls.do_handshake()
    except ssl.SSLWantReadError:pass
    hello=outgoing.read();result['hello_record_bytes']=len(hello);result['probe_marker_offset']=hello.find(token.encode())
    sock=None;before={};start=time.monotonic()
    try:
        sock=socket.create_connection(('89.125.90.101',443),timeout=7);sock.settimeout(7)
        # Disable Nagle for this TLS probe.
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        try:before=info(sock)
        except OSError as e:result['tcp_info_error']=type(e).__name__
        sock.sendall(hello);deadline=time.monotonic()+7
        while True:
            try:
                tls.do_handshake();result['tls_verified']=True;result['tls_version']=tls.version();break
            except ssl.SSLWantReadError:
                pending=outgoing.read()
                if pending:sock.sendall(pending)
                remaining=deadline-time.monotonic()
                if remaining<=0 or not select.select([sock],[],[],remaining)[0]:raise TimeoutError()
                data=sock.recv(65536)
                if not data:raise EOFError()
                incoming.write(data)
        pending=outgoing.read()
        if pending:sock.sendall(pending)
    except Exception as e:result['error']=type(e).__name__
    finally:
        if sock:
            try:
                after=info(sock);result['tcp_before_hello']=before;result['tcp_after']=after
                for field in ['bytes_acked','bytes_received','bytes_sent','bytes_retransmitted','total_retransmits']:
                    if field in before and field in after:result['delta_'+field]=after[field]-before[field]
            except Exception as e:result['tcp_info_error']=type(e).__name__
            sock.close()
    result['elapsed_ms']=round((time.monotonic()-start)*1000)
    print(json.dumps(result,sort_keys=True),flush=True)
print('MNEBYDNS_PHONE_TCP_CHECK_V1',flush=True)
for domain in ['youtubei.googleapis.com','rr1---sn-gxuo03g-ig3s.googlevideo.com']:
    for tls12 in [False,True]:test(domain,tls12)
