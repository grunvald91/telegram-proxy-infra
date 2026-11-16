import socket,struct,time,json,sys,datetime,re,importlib.util,collections
ROLE=sys.argv[1];LOCAL='89.125.90.101' if ROLE=='DE' else '188.120.254.223';DURATION=150
path='/opt/mnebydns-youtube-quic-43612369808/relay.py';spec=importlib.util.spec_from_file_location('relay_trace',path);mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
pattern=re.compile(rb'(?:[a-z0-9-]+\.)*(?:googlevideo\.com|googleusercontent\.com|googleapis\.com|google\.com|gstatic\.com|youtube\.com|antigravity\.google)(?![a-z0-9.-])',re.I)
start=time.monotonic();flows={};pending={};counter=0
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.3)
print(json.dumps({'role':ROLE,'ready':True,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'duration_seconds':DURATION}),flush=True)
while time.monotonic()-start<DURATION:
 try:b,addr=s.recvfrom(24000)
 except socket.timeout:continue
 if addr[0] not in ['eth0','tg-relay'] or len(b)<54 or b[12:14]!=b'\x08\x00':continue
 proto=b[23]
 if proto not in [6,17]:continue
 off=14+(b[14]&15)*4
 if len(b)<off+20:continue
 src,dst=socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34]);sp,dp=struct.unpack('!HH',b[off:off+4])
 if dp not in [443,19444] and sp not in [443,19444]:continue
 key=(proto,src,sp,dst,dp);rev=(proto,dst,dp,src,sp)
 forward=True
 if key not in flows and rev in flows:key=rev;forward=False
 if proto==6:
  hdr=(b[off+12]>>4)*4;payload=b[off+hdr:];flags=b[off+13];seq,ack=struct.unpack('!II',b[off+4:off+12])
 else:payload=b[off+8:];flags=0;seq=ack=0
 if key not in flows:
  if dp not in [443,19444]:continue
  name=None
  if proto==6 and len(payload)>6 and payload[0]==22 and payload[5]==1:
   m=pattern.search(payload)
   if m:name=m[0].decode().lower()
  elif proto==17 and payload and payload[0]&128:
   fragments=mod.initial_crypto_fragments(payload)
   if fragments:
    parts=pending.setdefault(key,{})
    for pos,data in fragments:
     if len(data)>len(parts.get(pos,b'')):parts[pos]=data
    hello,complete=mod.contiguous_hello(parts)
    if complete:
     name=mod.tls_hello_sni(hello);pending.pop(key,None)
     if name and not pattern.fullmatch(name.encode()):name=None
  if not name:continue
  counter+=1
  leg='ingress' if dst==LOCAL else ('wg' if dst.startswith('10.66.77.') else 'origin')
  flows[key]={'flow':counter,'host':name,'protocol':'TCP' if proto==6 else 'QUIC','leg':leg,'start_s':round(time.monotonic()-start,2),'client_to_server_bytes':0,'server_to_client_bytes':0,'packets_up':0,'packets_down':0,'rst':0,'fin':0,'server_first_record':None,'bins':{},'first_seq':seq,'max_client_ack':0}
 f=flows[key];direction='up' if forward else 'down';n=len(payload)
 f['client_to_server_bytes' if forward else 'server_to_client_bytes']+=n;f['packets_'+direction]+=1
 f['rst']+=bool(flags&4);f['fin']+=bool(flags&1)
 if proto==6 and not forward:
  delta=(ack-f['first_seq'])&0xffffffff
  if delta<2**30:f['max_client_ack']=max(f['max_client_ack'],delta)
  if payload and f['server_first_record'] is None:f['server_first_record']=payload[0]
 sec=int(time.monotonic()-start);bucket=f['bins'].setdefault(str(sec),[0,0]);bucket[0 if forward else 1]+=n
 if len(pending)>2000:pending.clear()
s.close()
for f in flows.values():
 f.pop('first_seq',None);print(json.dumps({'role':ROLE,'flow':f}),flush=True)
print(json.dumps({'role':ROLE,'done':True,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'flows':len(flows)}),flush=True)
