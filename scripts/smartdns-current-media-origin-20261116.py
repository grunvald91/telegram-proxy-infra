import socket,ssl,time,json,concurrent.futures,subprocess,datetime
HOSTS=['rr2---sn-gxuo03g-3c2z.googlevideo.com','rr1---sn-gxuo03g-vqnl.googlevideo.com','rr4---sn-4g5ednsd.googlevideo.com','lh3.googleusercontent.com']
def one(job):
 h,mode=job;t=time.monotonic();d={'host':h,'route':mode}
 try:
  if mode=='origin':
   ips=list(dict.fromkeys(v[4][0] for v in socket.getaddrinfo(h,443,socket.AF_INET,socket.SOCK_STREAM)));d['origin_ips']=ips;ip,port=ips[0],443
   assert ip not in ['89.125.90.101','188.120.254.223'],'resolver loops to ingress'
  elif mode=='inner_proxy':ip,port='127.0.0.1',15449
  else:ip,port='89.125.90.101',443
  with socket.create_connection((ip,port),4) as raw:
   raw.settimeout(5)
   with ssl.create_default_context().wrap_socket(raw,server_hostname=h) as s:
    d['tls']='PASS';d['tls_ms']=round((time.monotonic()-t)*1000)
    s.sendall(('GET /generate_204 HTTP/1.1\r\nHost: '+h+'\r\nConnection: close\r\n\r\n').encode());b=s.recv(2048);d['http']=b.split(b'\r\n')[0].decode(errors='replace');d['first_bytes']=len(b)
 except Exception as e:d['error']=type(e).__name__
 d['ms']=round((time.monotonic()-t)*1000);return d
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:r=list(pool.map(one,[(h,m) for h in HOSTS for m in ['origin','inner_proxy','public_proxy']]))
print(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'probes':r,'done':True}))
