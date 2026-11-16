"""Read-only 35-second owner TCP handshake observer; no payload storage or firewall edits."""
import socket,struct,time,json,subprocess,datetime
MARKERS={'4e5a1d4706841871bb795faef6608d49c9f0c26f5832e36d4d82b02d190819c2': 'video_lower', 'ae617752ad54d9fe7f00ab708f92ad3336c92ca52c8e0b156cbbfda1275bee9a': 'video_upper', '5d1332e081e3bab1b1f0c897c4a3242195000df048f14aa20aab5ba241faea06': 'site_control'}
START=time.monotonic();events=[];owned=set();flows={};seen=set()
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.25)
while time.monotonic()-START<35:
 try:b,addr=s.recvfrom(65535)
 except socket.timeout:continue
 if addr[0]=='lo' or len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
 ihl=(b[14]&15)*4;o=14+ihl
 if len(b)<o+20:continue
 src,dst=socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34]);sp,dp=struct.unpack('!HH',b[o:o+4]);flags=b[o+13];payload=b[o+(b[o+12]>>4)*4:]
 incoming=dst=='89.125.90.101' and dp==443;outgoing=src=='89.125.90.101' and sp==443
 if not(incoming or outgoing):continue
 client,port=(src,sp) if incoming else (dst,dp);flow=(client,port);label=flows.get(flow)
 if incoming and len(payload)>=43 and payload[0]==22 and payload[5]==1:
  marker=payload[11:43].hex()
  if marker in MARKERS:
   label=MARKERS[marker];owned.add(client);flows[flow]=label
   events.append(dict(kind='client_hello_arrived',client=client,port=port,label=label,payload_bytes=len(payload),ms=round(1000*(time.monotonic()-START))))
 if flags&2 or label:
  kind=('synack' if outgoing else 'syn') if flags&2 else ('server_tls_record' if outgoing and payload and payload[0] in [20,21,22,23] else 'server_data' if outgoing and payload else 'tcp_reset' if flags&4 else None)
  ident=(flow,kind)
  if kind and ident not in seen:
   seen.add(ident);events.append(dict(kind=kind,client=client,port=port,label=label,bytes=len(payload),ms=round(1000*(time.monotonic()-START))))
s.close()
result=[]
for e in events:
 if e['client'] not in owned:continue
 e['client']='owner_public_ip';e['label']=e.get('label') or flows.get((next(iter(owned)),e['port']))
 result.append(e)
services={}
for name in ['nginx.service','mnebydns-googlepilot.service','mnebydns-de89-public-quic-20261115.service']:
 p=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=4);services[name]=p.stdout.strip()
print(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),observation_seconds=35,production_changed=False,owner_detected=bool(owned),events=result,services=services)))
