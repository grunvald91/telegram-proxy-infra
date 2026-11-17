#!/usr/bin/env python3
"""Use the installed libcurl unchanged; observe its socket and normal TLS Random."""
import ctypes as C,ctypes.util,hashlib,json,os,socket,struct,time
lib=C.CDLL(ctypes.util.find_library('curl') or 'libcurl.so')
lib.curl_global_init.argtypes=[C.c_long];lib.curl_global_init(3)
lib.curl_easy_init.restype=C.c_void_p
lib.curl_easy_setopt.argtypes=[C.c_void_p,C.c_int];lib.curl_easy_setopt.restype=C.c_int
lib.curl_easy_perform.argtypes=[C.c_void_p];lib.curl_easy_perform.restype=C.c_int
lib.curl_easy_cleanup.argtypes=[C.c_void_p]
lib.curl_slist_append.argtypes=[C.c_void_p,C.c_char_p];lib.curl_slist_append.restype=C.c_void_p
lib.curl_slist_free_all.argtypes=[C.c_void_p]
lib.curl_version.restype=C.c_char_p
def tcp(fd):
    with socket.socket(fileno=os.dup(fd)) as s:b=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,256)
    out={'state':b[0]}
    for n,p,f in [('unacked_segments',24,'I'),('total_retransmits',100,'I'),('bytes_acked',120,'Q'),('bytes_received',128,'Q'),('bytes_sent',200,'Q'),('bytes_retransmitted',208,'Q')]:
        if len(b)>=p+C.sizeof(C.c_uint64 if f=='Q' else C.c_uint32):out[n]=struct.unpack_from('='+f,b,p)[0]
    return out
def test(domain,tls12):
    h=lib.curl_easy_init();state={};wire=bytearray();keep=[]
    result={'domain':domain,'tls12_only':tls12}
    @C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_int,C.c_int)
    def sockopt(user,fd,purpose):state['fd']=fd;return 0
    @C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_int)
    def close(user,fd):
        try:state['after']=tcp(fd)
        except OSError as e:state['tcp_info_error']=type(e).__name__
        try:os.close(fd)
        except OSError:pass
        return 0
    @C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_int,C.c_void_p,C.c_size_t,C.c_void_p)
    def debug(handle,kind,data,size,user):
        if kind==6 and len(wire)<16384 and 'probe' not in result:
            if 'before' not in state and 'fd' in state:
                try:state['before']=tcp(state['fd'])
                except OSError as e:state['tcp_info_error']=type(e).__name__
            wire.extend(C.string_at(data,size))
            if len(wire)>=43 and wire[0]==22 and wire[5]==1:
                result['probe']=hashlib.sha256(wire[11:43]).hexdigest()[:16]
                result['hello_record_bytes']=5+int.from_bytes(wire[3:5],'big')
        return 0
    @C.CFUNCTYPE(C.c_size_t,C.c_void_p,C.c_size_t,C.c_size_t,C.c_void_p)
    def discard(data,size,n,user):return size*n
    def opt(n,value):
        if isinstance(value,str):value=value.encode();keep.append(value);value=C.c_char_p(value)
        elif isinstance(value,int):value=C.c_long(value)
        rc=lib.curl_easy_setopt(h,n,value)
        if rc:raise RuntimeError('CURL_OPTION_'+str(n)+'_'+str(rc))
    addresses=lib.curl_slist_append(None,(domain+':443:89.125.90.101').encode())
    start=time.monotonic()
    try:
        for n,v in [(10002,'https://'+domain+'/'),(10004,''),(10177,'*'),(113,1),(84,2),(99,1),(75,1),(155,15000),(156,7000),(41,1),(10203,C.c_void_p(addresses)),(20148,sockopt),(20208,close),(20094,debug),(20011,discard)]:opt(n,v)
        if tls12:opt(32,6|(6<<16))
        result['curl_result']=lib.curl_easy_perform(h)
    finally:
        lib.curl_easy_cleanup(h);lib.curl_slist_free_all(addresses)
    result['elapsed_ms']=round((time.monotonic()-start)*1000)
    result.update({k:state[k] for k in ['before','after','tcp_info_error'] if k in state})
    for k in ['bytes_acked','bytes_received','bytes_sent','bytes_retransmitted','total_retransmits']:
        if k in state.get('before',{}) and k in state.get('after',{}):result['delta_'+k]=state['after'][k]-state['before'][k]
    print(json.dumps(result,sort_keys=True),flush=True)
print('MNEBYDNS_NORMAL_LIBCURL_CHECK_V1 '+lib.curl_version().decode(),flush=True)
for domain in ['youtubei.googleapis.com','rr1---sn-gxuo03g-ig3s.googlevideo.com']:
    for tls12 in [False,True]:test(domain,tls12)
