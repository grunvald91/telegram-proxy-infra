"""VPN-aware common DoT: real Googlevideo IPv4 addresses inside this VPN.
Private/public direct SmartDNS routing remains on its existing backend.
"""
import datetime,hashlib,json,os,pathlib,signal,socket,ssl,stat,struct,subprocess,sys,time
HOSTS=['rr1---sn-gxuo03g-3c2z.googlevideo.com','rr2---sn-gxuo03g-vqnl.googlevideo.com','rr4---sn-gxuo03g-vqnl.googlevideo.com']
ROOT=pathlib.Path('/opt/mnebydns-vpn-video-origin-20261116');UNIT='mnebydns-vpn-video-origin-20261116.service';UNIT_PATH=pathlib.Path('/etc/systemd/system')/UNIT
ROUTER=pathlib.Path('/etc/mnebydns/personal-sni/nginx.conf');ROUTER_UNIT='mnebydns-personal-sni-stream.service';PORT=8857;TIMER='mnebydns-vpn-video-origin-rollback-20261116'
PROBE=r'''
import json,socket,ssl,struct,sys
ip,port,host,qtype=sys.argv[1:];qtype=int(qtype)
def readn(s,n):
 b=b''
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p:raise EOFError('DNS stream closed')
  b+=p
 return b
q=struct.pack('!HHHHHH',19012,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+bytes([0])+struct.pack('!HH',qtype,1)
with socket.create_connection((ip,int(port)),4) as raw:
 raw.settimeout(6)
 with ssl.create_default_context().wrap_socket(raw,server_hostname='dns.mnebyvpn.site') as tls:
  tls.sendall(len(q).to_bytes(2,'big')+q);n=int.from_bytes(readn(tls,2),'big');b=readn(tls,n)
def skip(i):
 while b[i]:
  if b[i]&192==192:return i+2
  i+=b[i]+1
 return i+1
assert int.from_bytes(b[:2],'big')==19012
p=skip(12)+4;ips=[];types=[]
for _ in range(int.from_bytes(b[6:8],'big')):
 p=skip(p);t,c,ttl,n=struct.unpack('!HHIH',b[p:p+10]);p+=10;types.append(t)
 if t==1 and n==4:ips.append(socket.inet_ntoa(b[p:p+4]))
 p+=n
print(json.dumps({'host':host,'qtype':qtype,'rcode':b[3]&15,'answers':int.from_bytes(b[6:8],'big'),'ipv4':ips,'types':types}))
'''
def run(args,**kwargs):return subprocess.run(args,capture_output=True,text=True,timeout=20,**kwargs)
def checked(args,**kwargs):
 r=run(args,**kwargs)
 if r.returncode:raise RuntimeError('Command failed: '+str(args[:3])+' exit='+str(r.returncode))
 return r.stdout.strip()
def query(ip,port,host,qtype=1,uid=False):
 args=(['runuser','-u','mnebyvpn-xray','--'] if uid else [])+['python3','-',ip,str(port),host,str(qtype)]
 return json.loads(checked(args,input=PROBE))
def mapped(r):return r['rcode']==0 and r['ipv4']==['89.125.90.101']
def origin(r):return r['rcode']==0 and r['ipv4'] and not {'89.125.90.101','188.120.254.223'}.intersection(r['ipv4'])
def reload_router():
 checked(['/usr/sbin/nginx','-t','-c',str(ROUTER)])
 pid=int(checked(['systemctl','show',ROUTER_UNIT,'-p','MainPID','--value']));assert pid>1
 assert str(ROUTER).encode() in pathlib.Path('/proc',str(pid),'cmdline').read_bytes()
 os.kill(pid,signal.SIGHUP);time.sleep(.3)
def atomic(p,data):
 mode=p.stat().st_mode if p.exists() else 0o644
 t=p.with_name('.'+p.name+'.tmp');t.write_bytes(data);os.chmod(t,stat.S_IMODE(mode));os.replace(t,p)
def rollback():
 manifest=json.loads((ROOT/'manifest.json').read_text());backup=pathlib.Path(manifest['backup']);old=(backup/'nginx.conf').read_bytes();current=ROUTER.read_bytes();candidate=manifest['candidate_sha256']
 if hashlib.sha256(current).hexdigest()==candidate:atomic(ROUTER,old);reload_router()
 elif current!=old:raise RuntimeError('Concurrent router changes; retain backend and refuse overwrite')
 checked(['systemctl','disable','--now',UNIT])
 if manifest.get('certificate_hook'):
  hook=pathlib.Path(manifest['certificate_hook'])
  if hook.is_file() and hashlib.sha256(hook.read_bytes()).hexdigest()==manifest['certificate_hook_sha256']:hook.unlink()
 return {'rollback':True,'router_restored':True}
if len(sys.argv)>1 and sys.argv[1]=='rollback':print(json.dumps(rollback()));sys.exit()
if len(sys.argv)>1 and sys.argv[1]=='finalize':
 m=json.loads((ROOT/'manifest.json').read_text());assert hashlib.sha256(ROUTER.read_bytes()).hexdigest()==m['candidate_sha256']
 assert checked(['systemctl','is-active',UNIT])=='active' and origin(query('89.125.90.101',853,HOSTS[0],uid=True))
 checked(['systemctl','stop',TIMER+'.timer']);print(json.dumps({'finalized':True,'rollback_timer_stopped':True,'service':UNIT}));sys.exit()
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'production_mutations':False,'checks':[]}
assert pathlib.Path('/opt/mnebydns-dot/coredns').is_file()
assert not UNIT_PATH.exists() and not ROOT.exists(),'DNS compatibility service already exists'
assert checked(['systemctl','is-active',ROUTER_UNIT])=='active'
original=ROUTER.read_bytes();text=original.decode();assert text.count('proxy_pass $personal_dot_target;')==1
assert 'default 89.125.90.101:853;' in text and '10.66.77.2:8856;' in text and 'listen 0.0.0.0:8854;' in text
assert 'mneby_meta' not in checked(['nft','list','tables'])
with socket.socket() as test:test.bind(('127.0.0.1',PORT))
for host in HOSTS:
 r=query('89.125.90.101',853,host,uid=True);assert mapped(r);result['checks'].append({'phase':'vpn_before',**r})
nonvideo_before=query('89.125.90.101',853,'gemini.google.com',uid=True)
ROOT.mkdir(mode=0o755);backup=ROOT/'backup';backup.mkdir(mode=0o700);(backup/'nginx.conf').write_bytes(original);os.chmod(backup/'nginx.conf',0o600)
core=f'''tls://googlevideo.com:{PORT} {{
 bind 127.0.0.1
 tls /run/credentials/{UNIT}/fullchain.pem /run/credentials/{UNIT}/privkey.pem
 template IN AAAA {{ rcode NOERROR }}
 template IN HTTPS {{ rcode NOERROR }}
 template IN SVCB {{ rcode NOERROR }}
 forward . tls://9.9.9.9 tls://149.112.112.112 {{
  tls_servername dns.quad9.net
  max_concurrent 128
 }}
 cache 30
 errors
}}
tls://.:{PORT} {{
 bind 127.0.0.1
 tls /run/credentials/{UNIT}/fullchain.pem /run/credentials/{UNIT}/privkey.pem
 forward . tls://89.125.90.101:853 {{
  tls_servername dns.mnebyvpn.site
  max_concurrent 128
 }}
 errors
}}
'''
# CoreDNS directives require braces on separate lines.
for rr in ['AAAA','HTTPS','SVCB']:core=core.replace('template IN '+rr+' { rcode NOERROR }','template IN '+rr+' {\n  rcode NOERROR\n }')
(ROOT/'Corefile').write_text(core)
unit=f'''[Unit]
Description=MNEBYDNS Googlevideo origin answers for local VPN DoT clients
After=network-online.target mnebydns-dot.service
Wants=network-online.target
[Service]
Type=simple
ExecStart=/opt/mnebydns-dot/coredns -conf {ROOT}/Corefile
DynamicUser=yes
LoadCredential=fullchain.pem:/etc/letsencrypt/live/dns.mnebyvpn.site/fullchain.pem
LoadCredential=privkey.pem:/etc/letsencrypt/live/dns.mnebyvpn.site/privkey.pem
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=96M
MemorySwapMax=0
CPUQuota=50%
TasksMax=48
LimitNOFILE=1024
Restart=on-failure
RestartSec=3s
[Install]
WantedBy=multi-user.target
'''
UNIT_PATH.write_text(unit);os.chmod(UNIT_PATH,0o644)
route='''  upstream vpn_video_origin_backend {
    server 127.0.0.1:8857 max_fails=1 fail_timeout=5s;
    server 89.125.90.101:853 backup;
  }
  # Common DNS requests originating on this VPN server need original video IPs.
  map "$ssl_preread_server_name|$remote_addr" $vpn_video_dot_target {
    "~*^dns[.]mnebyvpn[.]site[|](?:89[.]125[.]90[.]101|127[.]0[.]0[.]1)$" vpn_video_origin_backend;
    default $personal_dot_target;
  }
'''
candidate=text.replace('  server {\n',route+'  server {\n',1).replace('proxy_pass $personal_dot_target;','proxy_pass $vpn_video_dot_target;');assert candidate!=text
manifest={'backup':str(backup),'candidate_sha256':hashlib.sha256(candidate.encode()).hexdigest()};(ROOT/'manifest.json').write_text(json.dumps(manifest));os.chmod(ROOT/'manifest.json',0o600)
# Durable rollback command, no credentials or subscriber state.
(ROOT/'rollback.py').write_text(pathlib.Path(__file__).read_text() if __file__!='<stdin>' else '')
# The source is copied to the root-only backup by the workflow before execution.
source=pathlib.Path('/tmp/mnebydns-vpn-video-origin-20261116.py');assert source.is_file()
(ROOT/'rollback.py').write_bytes(source.read_bytes());os.chmod(ROOT/'rollback.py',0o700)
checked(['systemctl','daemon-reload']);timer_armed=False;router_changed=False
try:
 checked(['systemctl','start',UNIT])
 for _ in range(50):
  try:
   with socket.create_connection(('127.0.0.1',PORT),.1):break
  except OSError:time.sleep(.1)
 else:raise RuntimeError('Staged DNS listener unavailable')
 for host in HOSTS:
  r=query('127.0.0.1',PORT,host);assert origin(r);result['checks'].append({'phase':'staged_origin',**r})
 for typ in [28,64,65]:
  r=query('127.0.0.1',PORT,HOSTS[0],typ);assert r['rcode']==0 and r['answers']==0;result['checks'].append({'phase':'staged_no_ipv6_or_hints',**r})
 r=query('127.0.0.1',PORT,'gemini.google.com');assert r['rcode']==nonvideo_before['rcode'] and set(r['ipv4'])==set(nonvideo_before['ipv4']);result['checks'].append({'phase':'staged_existing_nonvideo_policy',**r})
 assert ROUTER.read_bytes()==original,'Concurrent router modification'
 checked(['systemd-run','--quiet','--unit='+TIMER,'--on-active=5m','--collect','/usr/bin/python3',str(ROOT/'rollback.py'),'rollback']);timer_armed=True
 assert checked(['systemctl','is-active',TIMER+'.timer'])=='active'
 atomic(ROUTER,candidate.encode());router_changed=True;reload_router()
 for host in HOSTS:
  r=query('89.125.90.101',853,host,uid=True);assert origin(r);result['checks'].append({'phase':'vpn_after',**r})
 r=query('89.125.90.101',853,'gemini.google.com',uid=True);assert r['rcode']==nonvideo_before['rcode'] and set(r['ipv4'])==set(nonvideo_before['ipv4']);result['checks'].append({'phase':'vpn_nonvideo_policy_preserved',**r})
 checked(['systemctl','enable',UNIT])
 hook=pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/mnebydns-vpn-video-origin-20261116.sh')
 hook.parent.mkdir(parents=True,exist_ok=True)
 assert not hook.exists(),'Certificate hook already exists'
 hook.write_text('#!/bin/sh\nset -eu\nif [ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/dns.mnebyvpn.site ]; then\n  /usr/bin/systemctl try-restart '+UNIT+'\nfi\n');os.chmod(hook,0o755)
 manifest['certificate_hook']=str(hook);manifest['certificate_hook_sha256']=hashlib.sha256(hook.read_bytes()).hexdigest();(ROOT/'manifest.json').write_text(json.dumps(manifest))
 result.update(production_mutations=True,router_sha256=manifest['candidate_sha256'],backup=str(backup),rollback_timer=TIMER+'.timer',done=True)
 # Keep timer armed until the workflow validates external direct SmartDNS queries.
 print(json.dumps(result))
except Exception as error:
 result['error']=type(error).__name__+': '+str(error)
 result['new_service_log']=run(['journalctl','-u',UNIT,'-n','15','--no-pager','-o','cat']).stdout
 if router_changed:rollback()
 else:run(['systemctl','disable','--now',UNIT])
 if timer_armed:run(['systemctl','stop',TIMER+'.timer'])
 print(json.dumps(result));raise
