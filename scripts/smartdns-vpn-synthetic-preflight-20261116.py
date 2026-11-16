"""Isolated loopback SOCKS comparison. Production processes/configs are untouched."""
import concurrent.futures,datetime,json,os,pathlib,pwd,socket,ssl,struct,subprocess,tempfile,time
HOSTS=['rr2---sn-gxuo03g-3c2z.googlevideo.com','rr1---sn-gxuo03g-vqnl.googlevideo.com','rr4---sn-4g5ednsd.googlevideo.com','gemini.google.com','aicode.googleapis.com']
IPS=['89.125.90.101','188.120.254.223']
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'production_mutations':False,'tests':[]}
binary='/opt/xray/xray'
result['version']=subprocess.run([binary,'version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
account=pwd.getpwnam('mnebyvpn-xray')
def drop():
 os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
def readn(s,n):
 b=b''
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p:raise EOFError()
  b+=p
 return b
def probe(args):
 mode,port,host,ip=args;t=time.monotonic();row={'mode':mode,'host':host,'destination':ip};s=None
 try:
  s=socket.create_connection(('127.0.0.1',port),3);s.settimeout(7);s.sendall(b'\x05\x01\x00');assert readn(s,2)==b'\x05\x00'
  # Destination is an IP while the original hostname is present only in TLS.
  s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(ip)+struct.pack('!H',443))
  head=readn(s,4);assert head[1]==0,'SOCKS rejected'
  n={1:4,4:16}.get(head[3]);n=n if n else readn(s,1)[0];readn(s,n+2)
  s=ssl.create_default_context().wrap_socket(s,server_hostname=host);row['tls']='PASS'
  s.sendall(('GET /generate_204 HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
  row['http']=s.recv(2048).split(b'\r\n')[0].decode(errors='replace')
 except Exception as e:row['error']=type(e).__name__
 finally:
  if s:s.close()
 row['ms']=round(1000*(time.monotonic()-t));return row
with tempfile.TemporaryDirectory(prefix='smartdns-vpn-preflight-') as temp:
 folder=pathlib.Path(temp);os.chmod(folder,0o755)
 for mode in ['baseline','scoped_fakedns','all_sni']:
  guard=socket.socket();guard.bind(('127.0.0.1',0));port=guard.getsockname()[1];guard.close()
  inbound={'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}
  cfg={'log':{'loglevel':'warning'},'inbounds':[inbound],'outbounds':[{'protocol':'freedom','settings':{'domainStrategy':'UseIPv4'}}]}
  if mode!='baseline':inbound['sniffing']={'enabled':True,'destOverride':['fakedns'] if mode=='scoped_fakedns' else ['tls','http','quic'],'metadataOnly':False,'routeOnly':False}
  if mode=='scoped_fakedns':cfg['fakedns']=[{'ipPool':ip+'/32','poolSize':1} for ip in IPS]
  path=folder/(mode+'.json');path.write_text(json.dumps(cfg));os.chmod(path,0o644)
  check=subprocess.run([binary,'run','-test','-config',str(path)],capture_output=True,timeout=8,preexec_fn=drop)
  assert check.returncode==0,mode+' validation failed'
  with (folder/'process.log').open('wb') as log:
   p=subprocess.Popen([binary,'run','-config',str(path)],stdout=log,stderr=log,preexec_fn=drop)
   try:
    for _ in range(40):
     try:
      with socket.create_connection(('127.0.0.1',port),.1):pass
      break
     except OSError:time.sleep(.05)
    else:raise RuntimeError('Isolated listener unavailable')
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
     result['tests']+=list(pool.map(probe,[(mode,port,h,ip) for h in HOSTS for ip in IPS]))
   finally:
    p.terminate()
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
result['done']=True
print(json.dumps(result))
