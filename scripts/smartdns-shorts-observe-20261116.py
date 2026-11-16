"""Bounded passive observation of the active VPN. No routing/config changes.
Only domains, public origin metadata and transfer/error counters leave the server.
"""
import collections,datetime,hashlib,importlib.util,ipaddress,json,os,pathlib,pwd,re,signal,socket,struct,subprocess,sys,time
BASE=pathlib.Path('/run/mnebydns-shorts-observe-20261116');DURATION=150
STAMP=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
def emit(value):print(json.dumps(value),flush=True)
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=10);return p.stdout.strip()
def sockrows(uid):
 rows=[]
 for filename in ['tcp','tcp6','udp','udp6']:
  try:lines=pathlib.Path('/proc/net/'+filename).read_text().splitlines()[1:]
  except OSError:continue
  for line in lines:
   a=line.split()
   if len(a)<10 or int(a[7])!=uid:continue
   local,remote=a[1].split(':'),a[2].split(':')
   def addr(text):
    raw=bytes.fromhex(text)
    if len(raw)==4:return socket.inet_ntoa(raw[::-1])
    return socket.inet_ntop(socket.AF_INET6,b''.join(raw[i:i+4][::-1] for i in range(0,16,4)))
   rows.append({'proto':filename,'src':addr(local[0]),'sp':int(local[1],16),'dst':addr(remote[0]),'dp':int(remote[1],16),'state':a[3],'tx_queue':int(a[4].split(':')[0],16),'rx_queue':int(a[4].split(':')[1],16)})
 return rows
def counters():
 out={}
 for f in ['snmp6','netstat','snmp']:
  p=pathlib.Path('/proc/net/'+f)
  if not p.exists():continue
  lines=p.read_text().splitlines()
  if f=='snmp6':
   for line in lines:
    k,v=line.split()
    if any(x in k for x in ['NoRoutes','Errors','Discards']):out[k]=int(v)
  else:
   for i in range(0,len(lines)-1,2):
    keys,vals=lines[i].split(),lines[i+1].split()
    for k,v in zip(keys[1:],vals[1:]):
     if any(x in k for x in ['Retrans','Timeout','Abort','InErrors','RcvbufErrors','SndbufErrors','NoRoutes']):out[keys[0]+k]=int(v)
 return out
if sys.argv[1]=='launch':
 BASE.mkdir(mode=0o700,exist_ok=True);folder=BASE/str(int(time.time()));folder.mkdir(mode=0o700)
 out=folder/'trace.jsonl'
 with out.open('wb') as stream:p=subprocess.Popen([sys.executable,'-u',__file__,'capture',str(folder)],stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True)
 for _ in range(60):
  if (folder/'ready').exists():break
  if p.poll() is not None:raise RuntimeError('Observer exited before readiness')
  time.sleep(.1)
 else:raise RuntimeError('Observer did not start')
 emit({'folder':str(folder),'pid':p.pid,'ready':True,'utc':STAMP(),'duration_seconds':DURATION});sys.exit()
if sys.argv[1]=='collect':
 state=json.load(sys.stdin);folder=pathlib.Path(state['folder']);assert folder.parent==BASE
 for _ in range(DURATION+30):
  if (folder/'done').exists():break
  time.sleep(1)
 else:raise RuntimeError('Observer completion missing')
 sys.stdout.write((folder/'trace.jsonl').read_text());sys.exit()
assert sys.argv[1]=='capture';folder=pathlib.Path(sys.argv[2]);uid=pwd.getpwnam('mnebyvpn-xray').pw_uid
path='/opt/mnebydns-youtube-quic-43612369808/relay.py';spec=importlib.util.spec_from_file_location('quic_observe',path);mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
pattern=re.compile(rb'(?:[a-z0-9-]+\.)*(?:googlevideo\.com|googleusercontent\.com|googleapis\.com|google\.com|youtube\.com)(?![a-z0-9.-])',re.I)
config=json.loads(pathlib.Path('/etc/mnebyvpn/xray-canary.json').read_text());emit({'event':'snapshot','utc':STAMP(),'production_mutations':False,'provisioner':run(['systemctl','is-active','mnebyvpn-vpn-provisioner.service']),'legacy_canary':run(['systemctl','is-active','mnebyvpn-xray-canary.service']),'inbounds':[{k:v for k,v in x.items() if k in ['tag','listen','port','sniffing']} for x in config['inbounds']],'fake_pools':config.get('fakedns'),'meta_canary_present':'mneby_meta' in run(['nft','list','tables'])})
start=time.monotonic();before=counters();flows={};owned=set();udp_ports=set();last_refresh=0;index=0;rawtrace=None;tracer=None
# Attach syscall metadata only if the tool is already installed. Never trace reads/writes.
import shutil
pid=None
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  if (p/'comm').read_text().strip()=='xray' and b'/etc/mnebyvpn/xray-canary.json' in (p/'cmdline').read_bytes():pid=int(p.name)
 except OSError:pass
if shutil.which('strace') and pid:
 rawtrace=(folder/'connect.syscalls').open('wb');tracer=subprocess.Popen(['strace','-qq','-f','-e','trace=connect,getsockopt','-p',str(pid)],stdin=subprocess.DEVNULL,stdout=rawtrace,stderr=rawtrace)
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('eth0',0));s.settimeout(.2);(folder/'ready').touch();emit({'event':'ready','utc':STAMP(),'duration_seconds':DURATION,'strace_available':bool(tracer),'runtime_child':pid})
try:
 while time.monotonic()-start<DURATION:
  now=time.monotonic()-start
  if now-last_refresh>.5:
   rows=sockrows(uid);owned={(r['src'],r['sp'],r['dst'],r['dp']) for r in rows if r['dp']==443};udp_ports={r['sp'] for r in rows if r['proto'].startswith('udp')};last_refresh=now
  try:b,_=s.recvfrom(65535)
  except socket.timeout:continue
  if len(b)<42 or b[12:14]!=b'\x08\x00' or b[23] not in [6,17]:continue
  proto=b[23];off=14+(b[14]&15)*4
  if len(b)<off+(20 if proto==6 else 8):continue
  src,dst=socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34]);sp,dp=struct.unpack('!HH',b[off:off+4]);up=dp==443
  if not up and sp!=443:continue
  key=(proto,src,sp,dst,dp) if up else (proto,dst,dp,src,sp)
  if key not in flows:
   if not up or len(flows)>=2500:continue
   index+=1;flows[key]={'flow':index,'protocol':'TCP' if proto==6 else 'QUIC','host':None,'origin':dst,'vpn_owned':(src,sp,dst,dp) in owned or (proto==17 and sp in udp_ports),'start_s':round(now,2),'up_bytes':0,'down_bytes':0,'up_packets':0,'down_packets':0,'rst_up':0,'rst_down':0,'fin':0,'duplicate_payload_bytes':0,'first_reply_s':None,'last_s':round(now,2),'bins':{},'_seen':set(),'_hello':{},'_base':None,'_crypto':{}}
  f=flows[key];f['last_s']=round(now,2)
  if proto==6:
   n=(b[off+12]>>4)*4;payload=b[off+n:];flags=b[off+13];seq=struct.unpack('!I',b[off+4:off+8])[0]
   f['rst_up' if up else 'rst_down']+=bool(flags&4);f['fin']+=bool(flags&1)
   if payload:
    marker=(up,seq,len(payload))
    if marker in f['_seen']:f['duplicate_payload_bytes']+=len(payload)
    elif len(f['_seen'])<12000:f['_seen'].add(marker)
   if up and not f['host'] and payload and len(f['_hello'])<20:
    if f['_base'] is None and len(payload)>5 and payload[0]==22 and payload[5]==1:f['_base']=seq
    if f['_base'] is not None:
     offset=(seq-f['_base'])&0xffffffff
     if offset<16384:f['_hello'][offset]=payload
     merged=bytearray(16384);filled=bytearray(16384)
     for pos,data in f['_hello'].items():
      size=min(len(data),16384-pos);merged[pos:pos+size]=data[:size];filled[pos:pos+size]=b'1'*size
     end=filled.find(0);hello=merged[:end if end>=0 else 16384];m=pattern.search(hello)
     if m:f['host']=m[0].decode().lower()
  else:
   payload=b[off+8:]
   if up and not f['host'] and payload and payload[0]&128:
    fragments=mod.initial_crypto_fragments(payload)
    if fragments:
     for pos,data in fragments:
      if len(data)>len(f['_crypto'].get(pos,b'')):f['_crypto'][pos]=data
     hello,complete=mod.contiguous_hello(f['_crypto'])
     if complete:
      name=mod.tls_hello_sni(hello)
      if name and pattern.fullmatch(name.encode()):f['host']=name.lower()
  size=len(payload);f['up_bytes' if up else 'down_bytes']+=size;f['up_packets' if up else 'down_packets']+=1
  if not up and size and f['first_reply_s'] is None:f['first_reply_s']=round(now,2)
  pair=f['bins'].setdefault(str(int(now//5)*5),[0,0]);pair[0 if up else 1]+=size
finally:
 s.close()
 if tracer:
  tracer.send_signal(signal.SIGINT)
  try:tracer.wait(timeout=3)
  except subprocess.TimeoutExpired:tracer.kill();tracer.wait(timeout=2)
  rawtrace.close();text=(folder/'connect.syscalls').read_text(errors='replace');families=collections.Counter(re.findall(r'sa_family=(AF_[A-Z0-9]+)',text));errors=collections.Counter(re.findall(r'= -1 ([A-Z][A-Z0-9_]+)',text));emit({'event':'xray_connect_syscalls','families':dict(families),'statuses':dict(errors),'note':'EINPROGRESS is normal for nonblocking connect'});(folder/'connect.syscalls').unlink()
 after=counters();emit({'event':'kernel_counter_delta','values':{k:after[k]-before.get(k,0) for k in after if after[k]!=before.get(k,0)}})
 for f in flows.values():
  if not f['host']:continue
  for k in list(f):
   if k.startswith('_'):f.pop(k)
  emit({'event':'flow',**f})
 emit({'event':'done','utc':STAMP(),'flows_seen':len(flows),'google_flows':sum(bool(f['host']) for f in flows.values()),'production_mutations':False});(folder/'done').touch()
