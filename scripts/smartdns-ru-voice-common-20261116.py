import socket,struct,time,json,sys,datetime,re,importlib.util,collections
ROLE=sys.argv[1];LOCAL='89.125.90.101' if ROLE=='DE' else '188.120.254.223';DURATION=110
path='/opt/mnebydns-youtube-quic-43612369808/relay.py';spec=importlib.util.spec_from_file_location('relay_trace',path);mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
pattern=re.compile(rb'(?:[a-z0-9-]+\.)*(?:googlevideo\.com|googleusercontent\.com|googleapis\.com|google\.com|gstatic\.com|youtube\.com|antigravity\.google)(?![a-z0-9.-])',re.I)
start=time.monotonic();flows={};pending={};counter=0
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.3)
print(json.dumps({'role':ROLE,'ready':True,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'duration_seconds':DURATION}),flush=True)
while time.monotonic()-start<DURATION:
 try:b,addr=s.recvfrom(24000)
 except socket.timeout:continue
 if addr[0]=='lo' or len(b)<54 or b[12:14]!=b'\x08\x00':continue
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

import pathlib,subprocess,json,re,datetime,shutil
out={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def run(a):
 try:
  p=subprocess.run(a,capture_output=True,text=True,timeout=12);return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-500:]}
 except FileNotFoundError:return {'unavailable':True}
 except Exception as e:return {'error':type(e).__name__}
def sanitize(s):
 return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',lambda m:m[0] if m[0] in ['89.125.90.101','188.120.254.223','10.66.77.1','10.66.77.2','127.0.0.1','0.0.0.0','9.9.9.9','1.1.1.1','8.8.8.8'] else '<ip>',s)
interfaces=json.loads(run(['ip','-j','-d','link','show'])['stdout']);out['links']=[];out['tc']={}
for link in interfaces:
 name=link['ifname'];out['links'].append({k:v for k,v in link.items() if k in ['ifname','mtu','qdisc','operstate','flags','xdp','linkinfo']})
 if name=='lo' or name.startswith(('veth','br-','docker')):continue
 out['tc'][name]={direction:run(['tc','-j','filter','show','dev',name,direction]) for direction in ['ingress','egress']}
 out['tc'][name]['qdisc']=run(['tc','-j','qdisc','show','dev',name])
 out['tc'][name]['offload']=run(['ethtool','-k',name])
out['nft']=run(['nft','-a','list','ruleset']);out['iptables']=run(['iptables-save','-c'])
out['policy_rules']=run(['ip','rule','show']);out['routes']=run(['ip','route','show','table','all'])
out['bpf_net']=run(['bpftool','net']);out['bpf_cgroup']=run(['bpftool','cgroup','tree'])
out['bpf_pins']=[str(p) for p in pathlib.Path('/sys/fs/bpf').rglob('*')][:100]
out['network_stats']=run(['ip','-s','link','show']);out['queues']=run(['cat','/proc/net/netfilter/nfnetlink_queue'])
out['sysctl']=run(['sysctl','net.ipv4.conf.all.rp_filter','net.ipv4.conf.default.rp_filter','net.ipv4.tcp_mtu_probing','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.ipv4.tcp_syncookies','net.netfilter.nf_conntrack_count','net.netfilter.nf_conntrack_max'])
out['services']={}
for unit in ['nginx.service','telegram-nfqws.service','telegram-foreign-nfqws.service','mnebydns-youtube-quic-ru-43612369808.service']:
 props=['ActiveState','NRestarts','MainPID','MemoryCurrent','MemoryMax','LimitNOFILE','CPUQuotaPerSecUSec','ControlGroup'];q=run(['systemctl','show',unit,*['-p'+k for k in props]]);data=dict(line.split('=',1) for line in q.get('stdout','').splitlines() if '=' in line)
 group=data.get('ControlGroup','')
 if group:
  for name in ['cpu.stat','cpu.max','memory.events','memory.current']:
   p=pathlib.Path('/sys/fs/cgroup'+group)/name
   if p.exists():data[name]=p.read_text()
 data['recent_errors']=run(['journalctl','-u',unit,'--since','15 minutes ago','--no-pager','-p','warning','-o','cat'])
 out['services'][unit]=data
out['done']=True
nginx=run(['nginx','-T'])
text=nginx.get('stdout','')+'\n'+nginx.get('stderr','');selected=[];inside=False;depth=0
for line in text.splitlines():
 if re.search(r'map\s+\$ssl_preread_',line):inside=True;depth=0
 if inside:
  selected.append(line);depth+=line.count('{')-line.count('}')
  if depth<=0:inside=False
 elif re.match(r'\s*(listen|proxy_pass|proxy_connect_timeout|proxy_timeout|ssl_preread|resolver|proxy_protocol|preread_buffer_size|preread_timeout)\b',line):selected.append(line)
out['nginx_stream_routing']=selected
out['role']='RU'
print(sanitize(json.dumps(out)))
