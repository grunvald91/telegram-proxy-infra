#!/usr/bin/env python3
"""Bounded owner-only QUIC Initial metadata; handshake bytes stay only in RAM."""
import asyncio,hashlib,importlib.util,json,os,pathlib,socket,struct,subprocess,sys,threading,time,signal
ROOT=pathlib.Path(__file__).resolve().parent
BASE=pathlib.Path('/opt/mnebydns-h3-origin-diag-44096073096-1')
spec=importlib.util.spec_from_file_location('quic_receipt_relay',BASE/'relay.py');q=importlib.util.module_from_spec(spec);sys.modules[spec.name]=q;spec.loader.exec_module(q)
rows=[json.loads(x) for x in pathlib.Path('/run/mnebydns-normalcurl-44087349813-1/bindings.private.jsonl').read_text().splitlines()]
PHONE=next(x['address'] for x in rows if x['probe']=='da67f0a412cd9bb8')
seen={};latest={};lock=threading.Lock();stopping=False

def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def prefix_sni(hello):
 try:
  if len(hello)<40 or hello[0]!=1:return None
  b=hello[4:];i=34;i+=1+b[i];n=int.from_bytes(b[i:i+2],'big');i+=2+n;i+=1+b[i];end=i+2+int.from_bytes(b[i:i+2],'big');i+=2
  while i+4<=min(end,len(b)):
   typ,n=struct.unpack('!HH',b[i:i+4]);i+=4
   if typ==0:
    ext=b[i:i+n]
    if len(ext)<5:return None
    size=int.from_bytes(ext[3:5],'big')
    if ext[2]!=0 or 5+size>len(ext):return None
    return ext[5:5+size].decode('ascii').lower()
   i+=n
 except (IndexError,ValueError,UnicodeDecodeError):return None

def flow_key(src,port,data,latest):
 initial=src==PHONE and len(data)>6 and ((data[1:5]==bytes.fromhex('00000001') and data[0]&0xf0==0xc0) or (data[1:5]==bytes.fromhex('6b3343cf') and data[0]&0xf0==0xd0))
 key=(port,data[6:6+data[5]].hex()) if initial and 1<=data[5]<=20 else latest.get(port)
 return key,initial

def snapshot(e,kind):
 hello,done=q.contiguous_hello(e['parts']);name=prefix_sni(hello)
 if name and not (name.endswith(('.googlevideo.com','.googleapis.com','.youtube.com','.ytimg.com','.ggpht.com')) or name=='youtube.com'):name='<other>'
 emit('OWNER_QUIC_INITIAL_RECEIPT',{'phase':kind,'flow':e['token'],'domain':name,'first_utc':e['utc'],'elapsed_ms':round((time.monotonic()-e['start'])*1000),'client_datagrams':e['rx'],'server_datagrams':e['tx'],'server_bytes':e['txbytes'],'authenticated_initials':e['good'],'initials_without_extractable_crypto':e['bad'],'initial_versions':sorted(e['versions']),'contiguous_crypto_bytes':len(hello),'expected_hello_bytes':4+int.from_bytes(hello[1:4],'big') if len(hello)>=4 else None,'hello_complete':bool(done and hello),'same_offset_resize':e['resize'],'overlap_conflict':e['conflict'],'crypto_fragment_ranges':sorted([[k,len(v)] for k,v in e['parts'].items()])[:24]})

def delayed(key):
 time.sleep(3)
 with lock:
  if key in seen and not stopping:snapshot(seen[key],'after_3s')

def read_exact(f,n):
 b=b''
 while len(b)<n:
  v=f.read(n-len(b))
  if not v:return None
  b+=v
 return b

p=subprocess.Popen(['timeout','600','tcpdump','-i','eth0','-n','-U','-B','16384','-s','8192','-w','-','udp and host '+PHONE+' and host 89.125.90.101 and port 443'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
def stop(signum,frame):
 if p.poll() is None:p.send_signal(signal.SIGINT)
signal.signal(signal.SIGTERM,stop)
try:
 h=read_exact(p.stdout,24)
 if not h:raise RuntimeError('NO_PCAP_HEADER')
 endian='<' if h[:4]==b'\xd4\xc3\xb2\xa1' else '>'
 link=struct.unpack(endian+'I',h[20:24])[0]
 if link!=1:raise RuntimeError('ETHERNET_REQUIRED')
 (ROOT/'READY').write_text('READY\n');emit('OWNER_QUIC_WATCH_READY',True)
 while True:
  h=read_exact(p.stdout,16)
  if h is None:break
  _,_,cap,orig=struct.unpack(endian+'IIII',h)
  if cap>8192:raise RuntimeError('OVERSIZED_CAPTURE')
  b=read_exact(p.stdout,cap)
  if b is None:raise RuntimeError('TRUNCATED_PCAP')
  if len(b)<42 or b[12:14]!=b'\x08\x00':continue
  ihl=(b[14]&15)*4;ipend=14+int.from_bytes(b[16:18],'big')
  if b[23]!=17 or ihl<20 or len(b)<14+ihl+8:continue
  src=socket.inet_ntoa(b[26:30]);dst=socket.inet_ntoa(b[30:34]);sp,dp,n,_=struct.unpack('!HHHH',b[14+ihl:14+ihl+8]);data=b[14+ihl+8:min(14+ihl+n,ipend)]
  port=sp if src==PHONE else dp
  key,initial=flow_key(src,port,data,latest)
  if key is None:continue
  with lock:
   if src!='89.125.90.101':
    if len(seen)>=192 and key not in seen:continue
    if key not in seen:
     e={'token':hashlib.sha256(os.urandom(16)).hexdigest()[:12],'parts':{},'start':time.monotonic(),'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'rx':0,'tx':0,'txbytes':0,'good':0,'bad':0,'versions':set(),'resize':0,'conflict':False};seen[key]=e;latest[port]=key
     threading.Thread(target=delayed,args=(key,),daemon=True).start()
    e=seen[key];e['rx']+=1
    if initial:
     e['versions'].add(data[1:5].hex());frames=q.initial_crypto_fragments(data)
     if frames:
      e['good']+=1
      for off,part in frames:
       prev=e['parts'].get(off)
       if prev is not None:
        overlap=min(len(prev),len(part))
        if prev[:overlap]!=part[:overlap]:e['conflict']=True;continue
        if len(prev)!=len(part):e['resize']+=1
        if len(prev)>=len(part):continue
       e['parts'][off]=part
     else:e['bad']+=1
   elif key in seen:
    seen[key]['tx']+=1;seen[key]['txbytes']+=len(data)
finally:
 with lock:
  stopping=True
  for e in seen.values():snapshot(e,'final')
 if p.poll() is None:p.terminate()
 _,stats=p.communicate(timeout=5)
 import re
 drops=re.search(rb'(\d+) packets dropped by kernel',stats)
 emit('OWNER_QUIC_WATCH_FINISHED',{'flows':len(seen),'kernel_drops':int(drops[1]) if drops else None})
