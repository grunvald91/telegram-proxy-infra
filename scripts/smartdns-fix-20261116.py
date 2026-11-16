import pathlib,subprocess,hashlib,json,sys,time,ssl,socket,struct,shutil,os,datetime
import ast,hashlib,re
EXTRA=('account.mongodb.com','alberta.ca','analog.com','ansys.com','artifacts.elastic.co','axiomtek.com','badoo.com','badoocdn.com','bosch.de','brickset.com','bumble.com','census.gov')
OLD='''            existing=waiting.pieces.get(offset)
            if existing is not None and existing!=data:
                self.assembling.pop(source,None)
                self.counters['rejected']+=1
                return
            waiting.pieces[offset]=data'''
NEW='''            # Retransmission may change CRYPTO frame boundaries. Validate all
            # overlapping bytes, retaining the longest piece at a given offset.
            for previous_offset, previous in waiting.pieces.items():
                start=max(offset,previous_offset)
                end=min(offset+len(data),previous_offset+len(previous))
                if start<end and data[start-offset:end-offset]!=previous[start-previous_offset:end-previous_offset]:
                    self.assembling.pop(source,None)
                    self.counters['rejected']+=1
                    return
            existing=waiting.pieces.get(offset,b'')
            if len(data)>len(existing):
                waiting.pieces[offset]=data'''
def relay(s):
 assert s.count(OLD)==1,'QUIC source drift'
 s=s.replace(OLD,NEW)
 tree=ast.parse(s);node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TCP_ALLOWLIST_RULES' for t in n.targets))
 rules=ast.literal_eval(node.value)
 missing=[h for h in EXTRA if ('exact',h) not in rules]
 pos=s.index('TCP_ALLOWLIST_RULES = (')+len('TCP_ALLOWLIST_RULES = (')
 s=s[:pos]+''.join('\n    '+repr(('exact',h))+',' for h in missing)+s[pos:]
 compile(s,'relay.py','exec');return s,len(rules)+len(missing)
def wrapper(s,sha,count):
 s,n=re.subn(r'RELAY_SHA256 = "[0-9a-f]{64}"','RELAY_SHA256 = "'+sha+'"',s);assert n==1
 s,n=re.subn(r'len\(relay.TCP_ALLOWLIST_RULES\) != \d+',f'len(relay.TCP_ALLOWLIST_RULES) != {count}',s);assert n==1
 compile(s,'public.py','exec');return s
def watchdog(s):
 # Preserve personal SNI routing: the legacy certificate cannot serve it.
 marker='if (( failures < 3 )); then exit 0; fi'
 assert s.count(marker)==1
 return s.split(marker)[0]+marker+'\n# Legacy CoreDNS lacks the personal wildcard certificate; do not strand clients.\necho "PERSONAL_SNI_WATCH=UNHEALTHY_PERSONAL_ROUTE_PRESERVED"\nexit 1\n'
def pilot(s):
 assert 'worker_connections 192;' in s
 return s.replace('worker_connections 192;','worker_connections 2048;').replace('proxy_timeout 120s;','proxy_timeout 15m;')
def corefile(s):
 assert '# Protocol-specific origin DNS exceptions 20261116' not in s
 names=['stun.l.google.com']+[f'stun{i}.l.google.com' for i in range(1,5)]+['stun.services.mozilla.com','mtalk.google.com','mtalk4.google.com','time.google.com']+[f'alt{i}-mtalk.google.com' for i in range(1,9)]
 # Separate most-specific zones override wildcard synthetic answers for all RR types.
 block='\n# Protocol-specific origin DNS exceptions 20261116\n'+' '.join('tls://'+n+':853' for n in names)+' {\n    bind 89.125.90.101\n    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n    forward . tls://9.9.9.9 tls://149.112.112.112 {\n        tls_servername dns.quad9.net\n        health_check 30s\n    }\n    cache 30\n    errors\n}\n'
 return s+block

ROLE=sys.argv[1]
ROOT=pathlib.Path('/var/backups/mnebydns-fix-20261116-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S'))
ROOT.mkdir(mode=0o700,parents=True)
changes={};services=[];applied=[]
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=45)
 if p.returncode:raise RuntimeError('command failed: '+args[0]+' '+args[1]+': '+p.stderr[-400:])
 return p.stdout
def stage(path,new):
 p=pathlib.Path(path);old=p.read_text()
 if old==new:return
 backup=ROOT/str(p).lstrip('/');backup.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,backup)
 changes[str(p)]=(old,new)
def dns(host):
 ctx=ssl.create_default_context();q=struct.pack('!HHHHHH',491,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+b'\0\0\1\0\1'
 with socket.create_connection(('89.125.90.101',853),4) as raw:
  raw.settimeout(5)
  with ctx.wrap_socket(raw,server_hostname='dns.mnebyvpn.site') as s:
   s.sendall(struct.pack('!H',len(q))+q);data=b''
   while len(data)<2:data+=s.recv(2-len(data))
   n=int.from_bytes(data,'big');data=b''
   while len(data)<n:
    b=s.recv(n-len(data));assert b,'EOF';data+=b
   assert data[:2]==q[:2] and data[3]&15==0,'DNS error'
   return {'answers':int.from_bytes(data[6:8],'big'),'maps89':socket.inet_aton('89.125.90.101') in data}
try:
 rp=pathlib.Path('/opt/mnebydns-youtube-quic-43612369808/relay.py');source=rp.read_text()
 assert hashlib.sha256(rp.read_bytes()).hexdigest()=='bde13ba42945a6489c7fdc235996ff9858961bde27e2881759dc24112122d46f','live relay changed; refusing overwrite'
 updated,count=relay(source);stage(str(rp),updated)
 if ROLE=='DE':
  n=pathlib.Path('/etc/nginx/nginx.conf').read_text()
  assert all(re.search(r'\b'+re.escape(h)+r'\s+[^;]+;',n) for h in EXTRA),'TCP policy drift'
  p=pathlib.Path('/opt/mnebydns-de89-public-quic-20261115/public.py');stage(str(p),wrapper(p.read_text(),hashlib.sha256(updated.encode()).hexdigest(),count))
  p=pathlib.Path('/usr/local/sbin/mnebydns-personal-sni-watch');stage(str(p),watchdog(p.read_text()))
  p=pathlib.Path('/etc/mnebydns-googlepilot/nginx.conf');stage(str(p),pilot(p.read_text()))
  p=pathlib.Path('/opt/mnebydns-dot/Corefile');stage(str(p),corefile(p.read_text()))
  services=['mnebydns-googlepilot.service','mnebydns-dot.service','mnebydns-youtube-quic-de-43612369808.service','mnebydns-de89-public-quic-20261115.service']
 else:services=['mnebydns-youtube-quic-ru-43612369808.service']
 # Persist a root-only rollback that restores contents (preserving bind mounts).
 rollback=ROOT/'rollback.sh';lines=['#!/bin/bash','set -eu']
 import shlex
 for p in changes:lines.append('cat '+shlex.quote(str(ROOT/p.lstrip('/')))+' > '+shlex.quote(p))
 lines.append('systemctl restart '+' '.join(services));rollback.write_text('\n'.join(lines)+'\n');rollback.chmod(0o700)
 timer='mnebydns-fix-revert-'+ROLE.lower()+'-'+str(os.getpid())
 run(['systemd-run','--quiet','--unit='+timer,'--on-active=5m','/bin/bash',str(rollback)])
 for p,(old,new) in changes.items():
  pathlib.Path(p).write_text(new);applied.append(p)
 if ROLE=='DE':
  run(['bash','-n','/usr/local/sbin/mnebydns-personal-sni-watch'])
  run(['/usr/sbin/nginx','-t','-c','/etc/mnebydns-googlepilot/nginx.conf'])
 for unit in services:run(['systemctl','restart',unit])
 time.sleep(4)
 for unit in services:assert run(['systemctl','is-active',unit]).strip()=='active',unit
 checks={}
 if ROLE=='DE':
  for h in ['www.youtube.com','rr1---sn-gxuo03g-ig3s.googlevideo.com','www.google.com','stun.l.google.com','stun1.l.google.com','mtalk.google.com','time.google.com','example.org']:
   checks[h]=dns(h)
   assert checks[h]['answers']>0,h
   assert checks[h]['maps89']==(h in ['www.youtube.com','rr1---sn-gxuo03g-ig3s.googlevideo.com','www.google.com']),h
 run(['systemctl','stop',timer+'.timer'])
 print(json.dumps({'ok':True,'role':ROLE,'backup':str(ROOT),'changed':list(changes),'relay_sha256':hashlib.sha256(updated.encode()).hexdigest(),'rules':count,'services':services,'dns':checks}))
except Exception as e:
 if applied:
  for p in applied:pathlib.Path(p).write_text(changes[p][0])
  for unit in services:subprocess.run(['systemctl','restart',unit],capture_output=True,timeout=45)
 print(json.dumps({'ok':False,'role':ROLE,'error':str(e),'rolled_back':bool(applied),'backup':str(ROOT)}));sys.exit(1)
