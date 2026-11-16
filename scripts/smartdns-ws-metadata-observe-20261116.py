"""Bounded loopback WebSocket/VLESS metadata observer; no payload or UUID logging.
No ptrace, process restarts, firewall or production configuration changes.
"""
import base64,collections,datetime,hashlib,importlib.util,json,os,pathlib,re,socket,struct,subprocess,sys,time,uuid
BASE=pathlib.Path('/run/mnebydns-ws-metadata-20261116');DURATION=600
PATTERN=re.compile(rb'(?:[a-z0-9-]+\.)*(?:googlevideo\.com|youtube\.com|googleapis\.com|googleusercontent\.com|google\.com)(?![a-z0-9.-])',re.I)
RELAY=None
class NeedMore(Exception):pass
def addr(data,pos):
 if len(data)<=pos:raise NeedMore()
 kind=data[pos];pos+=1
 if kind in [1,3]:
  size=4 if kind==1 else 16
  if len(data)<pos+size:raise NeedMore()
  return socket.inet_ntop(socket.AF_INET if kind==1 else socket.AF_INET6,data[pos:pos+size]),pos+size,'IPv4' if kind==1 else 'IPv6'
 if kind==2:
  if len(data)<=pos:raise NeedMore()
  size=data[pos];pos+=1
  if len(data)<pos+size:raise NeedMore()
  return data[pos:pos+size].decode('ascii',errors='ignore').lower(),pos+size,'domain'
 raise ValueError('unknown_address_type')
def sni(data,parts):
 if len(data)>5 and data[0]==22 and data[5]==1:
  m=PATTERN.search(data[:16384]);return m[0].decode().lower() if m else None
 if RELAY and data and data[0]&128:
  fragments=RELAY.initial_crypto_fragments(data)
  if fragments:
   for pos,chunk in fragments:
    if pos+len(chunk)<32768 and len(chunk)>len(parts.get(pos,b'')):parts[pos]=chunk
   hello,complete=RELAY.contiguous_hello(parts)
   if complete:
    name=RELAY.tls_hello_sni(hello)
    if name and PATTERN.fullmatch(name.encode()):return name.lower()
 return None
class Flow:
 def __init__(self,target,port,family,protocol,start):
  self.target=target;self.port=port;self.family=family;self.protocol=protocol;self.host=target if PATTERN.fullmatch(target.encode()) else None;self.start=start;self.up=0;self.down=0;self.end=None;self.parts={};self.hello=b'';self.server_tls_record=None;self.mux_errors=0
 def feed(self,data,up):
  if up:
   self.up+=len(data)
   if not self.host:
    if self.protocol=='TCP' and len(self.hello)<16384:self.hello+=data;self.host=sni(self.hello,self.parts)
    elif self.protocol=='UDP':self.host=sni(data,self.parts)
  else:
   self.down+=len(data)
   if self.server_tls_record is None and data and self.protocol=='TCP':self.server_tls_record=data[0]
 def report(self):
  return {'host':self.host,'target':self.target if self.host else '<other>','family':self.family,'port':self.port,'protocol':self.protocol,'start_s':round(self.start,2),'up_bytes':self.up,'down_bytes':self.down,'first_server_tls_record':self.server_tls_record,'mux_errors':self.mux_errors}
class Vless:
 def __init__(self,known,groups,start):
  self.known=known;self.groups=groups;self.group=None;self.valid=None;self.cmd=None;self.raw=b'';self.downraw=b'';self.response=False;self.flows={};self.current={};self.buffers=[b'',b''];self.started=start;self.udpbuf=[b'',b''];self.closed=False
 def feed(self,data,up,now):
  if self.closed:return
  if up and self.cmd is None:
   self.raw+=data
   if len(self.raw)<19:return
   if self.raw[0]!=0:self.closed=True;return
   key=self.raw[1:17]
   self.valid=key in self.known
   if key not in self.groups:self.groups[key]=len(self.groups)+1
   self.group=self.groups[key];p=18+self.raw[17]
   if len(self.raw)<=p:return
   cmd=self.raw[p];p+=1
   if cmd in [1,2]:
    if len(self.raw)<p+3:return
    port=int.from_bytes(self.raw[p:p+2],'big')
    try:target,end,family=addr(self.raw,p+2)
    except NeedMore:return
    self.flows[0]=Flow(target,port,family,'TCP' if cmd==1 else 'UDP',now);p=end
   elif cmd!=3:self.closed=True;return
   self.cmd=cmd;data=self.raw[p:];self.raw=b''
  if not up and not self.response:
   self.downraw+=data
   if len(self.downraw)<2:return
   n=2+self.downraw[1]
   if len(self.downraw)<n:return
   data=self.downraw[n:];self.downraw=b'';self.response=True
  if self.cmd==1:self.flows[0].feed(data,up)
  elif self.cmd==2:
   which=0 if up else 1;self.udpbuf[which]+=data
   while len(self.udpbuf[which])>=2:
    n=int.from_bytes(self.udpbuf[which][:2],'big')
    if len(self.udpbuf[which])<n+2:break
    payload,self.udpbuf[which]=self.udpbuf[which][2:n+2],self.udpbuf[which][n+2:];self.flows[0].feed(payload,up)
  elif self.cmd==3:self.mux(data,up,now)
 def mux(self,data,up,now):
  which=0 if up else 1;self.buffers[which]+=data
  while len(self.buffers[which])>=2:
   b=self.buffers[which];n=int.from_bytes(b[:2],'big')
   if n<4 or n>512:self.closed=True;return
   if len(b)<2+n:return
   meta=b[2:2+n];sid=int.from_bytes(meta[:2],'big');status,option=meta[2:4];end=2+n;payload=b''
   if option&1:
    if len(b)<end+2:return
    size=int.from_bytes(b[end:end+2],'big');end+=2
    if len(b)<end+size:return
    payload=b[end:end+size];end+=size
   self.buffers[which]=b[end:]
   if up and status in [1,2] and len(meta)>4 and meta[4] in [1,2]:
    try:
     port=int.from_bytes(meta[5:7],'big');target,_,family=addr(meta,7);key=(sid,target,port)
     if key not in self.flows:self.flows[key]=Flow(target,port,family,'TCP' if meta[4]==1 else 'UDP',now)
     self.current[sid]=key
    except (NeedMore,ValueError):continue
   key=self.current.get(sid)
   if key in self.flows:
    if option&2:self.flows[key].mux_errors+=1
    self.flows[key].feed(payload,up)
class WebSocket:
 def __init__(self,vless):self.vless=vless;self.buffers=[b'',b''];self.headers=[False,False];self.http_status=None;self.parse_errors=0;self.close_frames=0
 def feed(self,data,up,now):
  which=0 if up else 1;self.buffers[which]+=data
  if len(self.buffers[which])>2**21:self.buffers[which]=b'';self.parse_errors+=1;return
  if not self.headers[which]:
   b=self.buffers[which]
   if b'\r\n\r\n' not in b:return
   header,_,self.buffers[which]=b.partition(b'\r\n\r\n');self.headers[which]=True
   if up:
    if not header.startswith(b'GET '):self.parse_errors+=1;return
    for line in header.split(b'\r\n'):
     if line.lower().startswith(b'sec-websocket-protocol:'):
      value=line.split(b':',1)[1].strip()
      try:self.vless.feed(base64.urlsafe_b64decode(value+b'='*((-len(value))%4)),True,now)
      except Exception:pass
   else:
    try:self.http_status=int(header.split(b'\r\n')[0].split()[1])
    except (ValueError,IndexError):pass
  while len(self.buffers[which])>=2:
   b=self.buffers[which];a,z=b[0:2];n=z&127;p=2
   if n in [126,127]:
    size=2 if n==126 else 8
    if len(b)<p+size:return
    n=int.from_bytes(b[p:p+size],'big');p+=size
   if n>2**20:self.buffers[which]=b'';self.parse_errors+=1;return
   mask=None
   if z&128:
    if len(b)<p+4:return
    mask=b[p:p+4];p+=4
   if len(b)<p+n:return
   payload,self.buffers[which]=b[p:p+n],b[p+n:]
   if mask:payload=bytes(x^mask[i%4] for i,x in enumerate(payload))
   opcode=a&15
   if opcode in [0,2]:self.vless.feed(payload,up,now)
   elif opcode==8:self.close_frames+=1
class TCPStream:
 def __init__(self,consumer,up,seq):self.consumer=consumer;self.up=up;self.base=seq;self.next=0;self.parts={}
 def feed(self,seq,data,now):
  if not data:return
  pos=(seq-self.base)&0xffffffff
  if pos<self.next:
   skip=self.next-pos
   if skip>=len(data):return
   data=data[skip:];pos=self.next
  if pos-self.next>2**21 or len(self.parts)>1000:return
  if len(data)>len(self.parts.get(pos,b'')):self.parts[pos]=data
  while self.next in self.parts:
   b=self.parts.pop(self.next);self.next+=len(b);self.consumer.feed(b,self.up,now)
def emit(value):print(json.dumps(value),flush=True)
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def main():
 global RELAY
 mode=sys.argv[1]
 if mode=='launch':
  BASE.mkdir(mode=0o700,exist_ok=True);folder=BASE/str(int(time.time()));folder.mkdir(mode=0o700)
  with (folder/'trace.jsonl').open('wb') as out:p=subprocess.Popen([sys.executable,'-u',__file__,'capture',str(folder)],stdin=subprocess.DEVNULL,stdout=out,stderr=out,start_new_session=True)
  for _ in range(60):
   if (folder/'ready').exists():break
   if p.poll() is not None:raise RuntimeError('Observer startup failed')
   time.sleep(.1)
  else:raise RuntimeError('Observer startup timeout')
  emit({'ready':True,'folder':str(folder),'pid':p.pid,'utc':stamp(),'duration_seconds':DURATION});return
 if mode=='collect':
  state=json.load(sys.stdin);folder=pathlib.Path(state['folder']);assert folder.parent==BASE
  (folder/'stop').touch()
  for _ in range(15):
   if (folder/'done').exists():break
   time.sleep(1)
  else:raise RuntimeError('Completion missing')
  sys.stdout.write((folder/'trace.jsonl').read_text());return
 assert mode=='capture';folder=pathlib.Path(sys.argv[2]);cfg=json.loads(pathlib.Path('/etc/mnebyvpn/xray-canary.json').read_text());known={uuid.UUID(c['id']).bytes for i in cfg['inbounds'] for c in i['settings'].get('clients',[])};groups={};sessions={}
 spec=importlib.util.spec_from_file_location('quic_ws_observe','/opt/mnebydns-youtube-quic-43612369808/relay.py');RELAY=importlib.util.module_from_spec(spec);sys.modules[spec.name]=RELAY;spec.loader.exec_module(RELAY)
 emit({'event':'snapshot','utc':stamp(),'configured_client_count':len(known),'production_mutations':False,'observer':'loopback AF_PACKET only; no ptrace','config_sha256':hashlib.sha256(pathlib.Path('/etc/mnebyvpn/xray-canary.json').read_bytes()).hexdigest(),'inbounds':[{k:v for k,v in x.items() if k in ['tag','listen','port','sniffing']} for x in cfg['inbounds']],'fake_pools':cfg.get('fakedns'),'outbounds':[{'tag':x.get('tag'),'protocol':x['protocol'],'domainStrategy':x.get('settings',{}).get('domainStrategy')} for x in cfg.get('outbounds',[])]})
 start=time.monotonic();s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('lo',0));s.settimeout(.2);(folder/'ready').touch();emit({'event':'ready','utc':stamp(),'duration_seconds':DURATION})
 try:
  while time.monotonic()-start<DURATION and not (folder/'stop').exists():
   try:b,address=s.recvfrom(262144)
   except socket.timeout:continue
   if address[2]==socket.PACKET_OUTGOING or len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
   total=int.from_bytes(b[16:18],'big');b=b[:14+total];off=14+(b[14]&15)*4
   if len(b)<off+20:continue
   sp,dp=struct.unpack('!HH',b[off:off+4]);up=dp==18943
   if not up and sp!=18943:continue
   key=sp if up else dp;flags=b[off+13];seq=int.from_bytes(b[off+4:off+8],'big');header=(b[off+12]>>4)*4;payload=b[off+header:];now=time.monotonic()-start
   if flags&2:
    if up and not flags&16:
     if len(sessions)>=2000:continue
     v=Vless(known,groups,now);ws=WebSocket(v);sessions[key]={'ws':ws,'v':v,'up':TCPStream(ws,True,(seq+1)&0xffffffff),'down':None,'rst_up':0,'rst_down':0,'start_s':round(now,2)}
    elif not up and key in sessions:sessions[key]['down']=TCPStream(sessions[key]['ws'],False,(seq+1)&0xffffffff)
   if key not in sessions:continue
   session=sessions[key];session['rst_up' if up else 'rst_down']+=bool(flags&4)
   stream=session['up' if up else 'down']
   if stream:
    try:stream.feed(seq,payload,now)
    except (ValueError,IndexError,struct.error):session['ws'].parse_errors+=1
 finally:
  s.close();google=0
  for index,session in enumerate(sessions.values(),1):
   v=session['v'];ws=session['ws'];summary={'event':'session','session':index,'client_group':v.group,'authorized':v.valid,'vless_command':v.cmd,'http_status':ws.http_status,'start_s':session['start_s'],'rst_up':session['rst_up'],'rst_down':session['rst_down'],'parse_errors':ws.parse_errors,'close_frames':ws.close_frames,'flow_count':len(v.flows),'families':dict(collections.Counter(f.family for f in v.flows.values())),'response_header_received':v.response,'zero_reply_flows':sum(f.down==0 for f in v.flows.values()),'total_up_bytes':sum(f.up for f in v.flows.values()),'total_down_bytes':sum(f.down for f in v.flows.values())};emit(summary)
   for f in v.flows.values():
    if f.host:emit({'event':'flow','session':index,'client_group':v.group,**f.report()});google+=1
  emit({'event':'done','utc':stamp(),'sessions':len(sessions),'client_groups':len(groups),'google_flows':google,'production_mutations':False});(folder/'done').touch()
if __name__=='__main__':main()
