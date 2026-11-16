"""Read-only bounded TCP reassembly metadata; no packet contents persisted."""
import socket,struct,time,json,subprocess,datetime,pathlib,hashlib
MARKERS={'36ad283ffcba50d5e07ef4db823106afbc1c80030d2ea91b56bfb3ed06802477': 'video_lower_large', 'd12583c06f79b5a1741ec5a3c9136ba394eb9eaeac749628c83e731fbfbaffc0': 'video_upper_large', '05accab9bdfe5067eecd0a8606393eae8766e31cb742042d01fe5382b1eb246c': 'video_lower_tls12', '5a75ec4dae8535c70cbfa9e90cf799400db462a2aab821df84a13ebf649e4022': 'video_upper_tls12'}
start=time.monotonic();flows={};reverse={};seen=set();s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.25)
while time.monotonic()-start<35:
 try:b,addr=s.recvfrom(65535)
 except socket.timeout:continue
 if len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
 off=14+(b[14]&15)*4
 if len(b)<off+20:continue
 src,dst=socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34]);sp,dp=struct.unpack('!HH',b[off:off+4]);seq,ack=struct.unpack('!II',b[off+4:off+12]);flags=b[off+13];payload=b[off+(b[off+12]>>4)*4:]
 key=(src,sp,dst,dp);rev=(dst,dp,src,sp)
 if len(payload)>=43 and payload[0]==22 and payload[5]==1 and payload[11:43].hex() in MARKERS:
  if key not in flows:
   stage='googlepilot_loopback' if dp==15449 else 'public_ingress' if dst=='89.125.90.101' and dp==443 else 'google_origin_egress'
   flows[key]=dict(label=MARKERS[payload[11:43].hex()],stage=stage,interface=addr[0],expected_clienthello_bytes=5+int.from_bytes(payload[3:5],'big'),first_seq=seq,events=[],ranges=[])
 if key in flows:f=flows[key];direction='client_to_server'
 elif rev in flows:f=flows[rev];direction='server_to_client'
 else:continue
 ident=(key,seq,ack,flags,len(payload),addr[0])
 if ident in seen:continue
 seen.add(ident)
 e=dict(direction=direction,bytes=len(payload),flags=flags,ms=round(1000*(time.monotonic()-start)))
 if direction=='client_to_server':
  e['client_seq_offset']=(seq-f['first_seq'])%(2**32)
  if payload:f['ranges'].append([e['client_seq_offset'],e['client_seq_offset']+len(payload)])
 else:e['acknowledged_client_bytes']=(ack-f['first_seq'])%(2**32)
 if payload:e['tls_record_type']=payload[0] if payload[0] in [20,21,22,23] else None
 if len(f['events'])<70:f['events'].append(e)
s.close();result=[]
for f in flows.values():
 f.pop('first_seq');ranges=sorted(f.pop('ranges'));end=0
 for a,b in ranges:
  if a>end:break
  end=max(end,b)
 f['contiguous_client_bytes_observed']=end;f['complete_clienthello_observed']=end>=f['expected_clienthello_bytes'];result.append(f)
configs={}
for name in ['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf']:
 p=pathlib.Path(name);text=p.read_text();configs[name]=dict(sha256=hashlib.sha256(p.read_bytes()).hexdigest(),selected=[line.strip() for line in text.splitlines() if any(x in line for x in ['googlevideo','resolver ','proxy_pass','listen 127.0.0.1:15449','ssl_preread','proxy_protocol'])])
print(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),observation_seconds=35,production_changed=False,flows=result,configs=configs)))
