"""Isolated loopback SOCKS comparison. Validate on loopback, then apply with backup and rollback."""
import concurrent.futures,datetime,json,os,pathlib,pwd,socket,ssl,struct,subprocess,tempfile,time,hashlib,copy,grp,threading
HOSTS=['rr2---sn-gxuo03g-3c2z.googlevideo.com','rr1---sn-gxuo03g-vqnl.googlevideo.com','rr4---sn-4g5ednsd.googlevideo.com','gemini.google.com','aicode.googleapis.com']
IPS=['89.125.90.101','188.120.254.223']
# The installed Xray rejects /32 pools: its LRU check requires pool size < address count.
POOLS=[{'ipPool':'89.125.90.100/31','poolSize':1},{'ipPool':'188.120.254.222/31','poolSize':1}]
SNIFF={'enabled':True,'destOverride':['fakedns'],'metadataOnly':False,'routeOnly':False}
CONF=pathlib.Path('/etc/mnebyvpn/xray-canary.json')
original=CONF.read_bytes();production=json.loads(original)
assert 'mneby_meta' not in subprocess.run(['nft','list','tables'],capture_output=True,text=True,check=True).stdout
assert 'fakedns' not in production
ws=next(i for i in production['inbounds'] if i['tag']=='mnebyvpn-inbound')
assert ws['listen']=='127.0.0.1' and ws['port']==18943 and not ws.get('sniffing')
assert ws['streamSettings']['network']=='ws'
assert all(o['protocol'] in ['freedom','blackhole'] for o in production['outbounds'])
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
 for mode in ['baseline','scoped_fakedns']:
  guard=socket.socket();guard.bind(('127.0.0.1',0));port=guard.getsockname()[1];guard.close()
  inbound={'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}
  cfg={'log':{'loglevel':'warning'},'inbounds':[inbound],'outbounds':[{'protocol':'freedom','settings':{}}]}
  if mode!='baseline':inbound['sniffing']={'enabled':True,'destOverride':['fakedns'] if mode=='scoped_fakedns' else ['tls','http','quic'],'metadataOnly':False,'routeOnly':False}
  if mode=='scoped_fakedns':cfg['fakedns']=POOLS
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
    else:
     log.flush();result['tests'].append({'mode':mode,'startup_error':(folder/'process.log').read_text()[-3000:],'exit':p.poll()});continue
    if mode=='scoped_fakedns':
     # An HTTP Host outside the pool must not replace a real destination.
     with socket.socket() as control:
      control.bind(('127.0.0.1',0));control.listen();control.settimeout(5);control_port=control.getsockname()[1]
      def answer():
       with control.accept()[0] as peer:
        peer.settimeout(3);peer.recv(2048);peer.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
      thread=threading.Thread(target=answer,daemon=True);thread.start()
      with socket.create_connection(('127.0.0.1',port),3) as peer:
       peer.settimeout(4);peer.sendall(b'\x05\x01\x00');assert readn(peer,2)==b'\x05\x00'
       peer.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',control_port))
       head=readn(peer,4);assert head[1]==0;readn(peer,6)
       peer.sendall(b'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n');assert peer.recv(2048).startswith(b'HTTP/1.1 204')
      thread.join(timeout=1);result['non_pool_destination_preserved']=True
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
     result['tests']+=list(pool.map(probe,[(mode,port,h,ip) for h in HOSTS for ip in IPS]))
   finally:
    p.terminate()
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)

scoped=[r for r in result['tests'] if r['mode']=='scoped_fakedns']
assert len(scoped)==10 and all(r.get('tls')=='PASS' and r.get('http','').startswith('HTTP/1.1 204') for r in scoped),'Scoped preflight failed'
def topology(cfg):
 c=copy.deepcopy(cfg)
 for inbound in c.get('inbounds',[]):inbound.get('settings',{}).pop('clients',None)
 return c
fresh=CONF.read_bytes()
if topology(json.loads(fresh))!=topology(production):
 result['error']='Concurrent VPN topology change';print(json.dumps(result));raise RuntimeError(result['error'])
result['concurrent_client_config_update']=fresh!=original
original=fresh;production=json.loads(fresh)
candidate=copy.deepcopy(production);candidate['fakedns']=POOLS
next(i for i in candidate['inbounds'] if i['tag']=='mnebyvpn-inbound')['sniffing']=SNIFF
folder=pathlib.Path('/opt/mnebyvpn/backups/smartdns-vpn-20261116-'+str(int(time.time())))
folder.mkdir(mode=0o700,parents=True)
backup=folder/'xray-canary.json';backup.write_bytes(original);os.chmod(backup,0o600)
new=folder/'candidate.json';new.write_text(json.dumps(candidate,indent=2)+'\n');os.chmod(new,0o600)
checked=subprocess.run([binary,'run','-test','-config',str(new)],capture_output=True,timeout=8)
assert checked.returncode==0,'Production candidate validation failed'
unit='mnebyvpn-vpn-provisioner.service'
def replace_conf(raw):
 tmp=CONF.with_name('.xray-canary-smartdns.tmp');tmp.write_bytes(raw);os.chmod(tmp,0o640);os.chown(tmp,0,account.pw_gid);os.replace(tmp,CONF)
def service(*args):
 subprocess.run(['systemctl',*args,unit],check=True,capture_output=True,timeout=20)
applied=False
try:
 service('stop')
 stopped=CONF.read_bytes()
 assert topology(json.loads(stopped))==topology(production),'Concurrent topology changed before stop'
 if stopped!=original:
  original=stopped;backup.write_bytes(original)
  candidate=json.loads(stopped);candidate['fakedns']=POOLS
  next(i for i in candidate['inbounds'] if i['tag']=='mnebyvpn-inbound')['sniffing']=SNIFF
  new.write_text(json.dumps(candidate,indent=2)+'\n')
 replace_conf(new.read_bytes());applied=True;service('start')
 assert subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,check=True).stdout.strip()=='active'
 with socket.create_connection(('127.0.0.1',18943),3):pass
 active=json.loads(CONF.read_text());assert active['fakedns']==POOLS
 assert next(i for i in active['inbounds'] if i['tag']=='mnebyvpn-inbound')['sniffing']==SNIFF
 # Child running with the candidate and parent has reloaded its persistent template.
 pids=[]
 for entry in pathlib.Path('/proc').iterdir():
  if not entry.name.isdigit():continue
  try:
   if (entry/'comm').read_text().strip()=='xray' and str(CONF).encode() in (entry/'cmdline').read_bytes():pids.append(int(entry.name))
  except OSError:pass
 assert len(pids)==1,'Expected one active VPN child'
 result.update(production_mutations=True,backup=str(backup),runtime_child=pids[0],config_sha256=hashlib.sha256(CONF.read_bytes()).hexdigest(),scoped_pools=POOLS,rollback=False)
except Exception:
 service('stop')
 if applied:replace_conf(original)
 service('start');result['rollback']=applied
 print(json.dumps(result));raise
result['done']=True
print(json.dumps(result))
