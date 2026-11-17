#!/usr/bin/env python3
"""Read-only ingress, stream return-path and alternate-entry audit. No secrets."""
import hashlib,json,pathlib,re,socket,ssl,subprocess,sys,time

ROLE=sys.argv[1]
PUBLIC={'DE':'89.125.90.101','RU':'188.120.254.223'}[ROLE]
KNOWN={'89.125.90.101','188.120.254.223','10.66.77.1','10.66.77.2','127.0.0.1','0.0.0.0','1.1.1.1','8.8.8.8','9.9.9.9','149.112.112.112'}
IP=re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?(?![\d.])')
TARGET=re.compile(r'googlevideo|youtubei|ytimg|gstatic',re.I)
def scrub(s):
 s=IP.sub(lambda m:m[0] if m[0] in KNOWN else '<ip-'+hashlib.sha256(m[0].encode()).hexdigest()[:8]+'>',s)
 s=re.sub(r'[a-z0-9_-]+\.dns\.mnebyvpn\.site','<personal-label>.dns.mnebyvpn.site',s,flags=re.I)
 s=re.sub(r'https?://[^\s\"\']+','<url>',s)
 return re.sub(r'\b[a-f0-9]{32,}\b','<hex>',s,flags=re.I)
def run(args,timeout=12):
 try:
  r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  return r.returncode,r.stdout
 except (OSError,subprocess.TimeoutExpired) as e:return -1,type(e).__name__
def emit(name,obj):print(ROLE+' '+name+'='+scrub(obj if isinstance(obj,str) else json.dumps(obj,sort_keys=True)),flush=True)

for u in ['nginx','mnebydns-googlepilot','mnebydns-dot','telegram-foreign-nfqws']:
 emit('SERVICE_'+u,run(['systemctl','is-active',u])[1].strip())
emit('LISTENERS',run(['ss','-Hlnpt','( sport = :22 or sport = :443 or sport = :853 or sport = :15449 )'])[1])
rc,raw=run(['nft','-j','list','ruleset'])
if rc==0:
 for item in json.loads(raw).get('nftables',[]):
  r=item.get('rule')
  if not r:continue
  expr=r.get('expr',[]);encoded=json.dumps(expr)
  if any(k in e for e in expr for k in ['queue','mangle','tproxy','redirect','notrack']):emit('PACKET_TRANSFORM',r)
  elif any(k in e for e in expr for k in ['drop','reject']):
   emit('DROP_SUMMARY',{'family':r.get('family'),'table':r.get('table'),'chain':r.get('chain'),'handle':r.get('handle'),'extensions':re.findall(r'"name": "([^"]+)"',encoded),'counter':[e['counter'] for e in expr if 'counter' in e]})
rc,raw=run(['ip','-j','link','show'])
if rc==0:
 for link in json.loads(raw):
  if 'xdp' in link:emit('XDP',{'interface':link['ifname'],'xdp':link['xdp']})
for interface in ['eth0' if ROLE=='DE' else 'ens3','tg-relay']:
 emit('TC_INGRESS_'+interface,run(['tc','filter','show','dev',interface,'ingress'])[1])
 emit('TC_EGRESS_'+interface,run(['tc','filter','show','dev',interface,'egress'])[1])
emit('POLICY_RULES',run(['ip','rule','show'])[1])
emit('NFQUEUE_STATS',run(['cat','/proc/net/netfilter/nfnetlink_queue'])[1])

for config in ['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf']:
 if not pathlib.Path(config).is_file():continue
 emit('CONFIG_SHA',{'path':config,'sha256':hashlib.sha256(pathlib.Path(config).read_bytes()).hexdigest()})
 rc,raw=run(['nginx','-T','-c',config]);emit('NGINX_TEST',{'config':config,'exit':rc})
 for line in raw.splitlines():
  if TARGET.search(line) or re.match(r'\s*(proxy_timeout|preread_timeout|preread_buffer_size|proxy_buffer_size|proxy_connect_timeout|resolver|ssl_preread|listen|proxy_pass|access_log|error_log)\s',line):
   if len(line)>400:line='<family route target='+line.strip().split()[-1]+' googlevideo='+str('googlevideo' in line)+'>'
   emit('NGINX_DIRECTIVE',line.strip())
 for name,fmt in re.findall(r'\blog_format\s+(\S+)\s+([^;]+);',raw):
  if 'stream' in name or 'ssl_preread' in fmt:emit('STREAM_LOG_FORMAT',name+' '+fmt)
 paths=set(re.findall(r'\b(?:access_log|error_log)\s+(/var/log/[^;\s]+)',raw))
 for path in sorted(paths):
  if not any(x in path for x in ['stream','googlepilot','mnebydns']):continue
  rc,tail=run(['tail','-n','200',path])
  selected=[line for line in tail.splitlines() if TARGET.search(line)]
  emit('TARGET_LOG_TAIL',{'path':path,'matching_lines':len(selected),'lines':selected[-16:]})

API='youtubei.googleapis.com';CDN='rr1---sn-gxuo03g-ig3s.googlevideo.com'
paths=[('LOOP','127.0.0.1'),('PRIVATE_DE','10.66.77.1'),('DE_PUBLIC','89.125.90.101')]
if ROLE=='RU':paths=[('RU_LOCAL','127.0.0.1'),('DE_PRIVATE','10.66.77.1'),('DE_PUBLIC','89.125.90.101')]
for label,addr in paths:
 for host in [API,CDN]:
  start=time.monotonic();result={'path':label,'host':host}
  try:
   with socket.create_connection((addr,443),timeout=4) as raw:
    raw.settimeout(4)
    with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
     result['tls']=tls.version();result['certificate_verified']=True
     tls.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
     result['http']=tls.recv(100).split(b'\r\n')[0].decode('ascii','replace')
  except Exception as e:result['error']=type(e).__name__
  result['ms']=round((time.monotonic()-start)*1000);emit('TLS_CONTROL',result)
emit('AUDIT_CONFIGURATION_CHANGED',False)
