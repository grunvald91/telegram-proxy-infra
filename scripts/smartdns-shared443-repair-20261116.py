import subprocess,socket,struct,time,pathlib,json,sys,datetime,os
START=1794813446
TRIGGER='e40adcf50566b14e0499bce6f38ae2d824004f7f3f56a88c16fcca32e1066163'
CONFIRM='8fb3ca60a5de28c6468edad2c30eb2dd212de4eb07a29a889ec533d58f8be46f'
FAMILY='inet';TABLE='mneby_meta_v26_ru';LOCAL='188.120.254.223'
OUT={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'operation':'restore shared public443 from source-IP-wide experimental DNAT'}
def run(a,stdin=None):
 p=subprocess.run(a,input=stdin,capture_output=True,text=True,timeout=12)
 if p.returncode:raise RuntimeError('command failed '+a[0]+': '+p.stderr[-400:])
 return p.stdout
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.3)
def marker_seen(marker,until):
 while time.time()<until:
  try:b,addr=s.recvfrom(10000)
  except socket.timeout:continue
  if addr[0]=='lo' or len(b)<90 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
  off=14+(b[14]&15)*4
  if len(b)<off+20:continue
  sp,dp=struct.unpack('!HH',b[off:off+4]);p=b[off+(b[off+12]>>4)*4:]
  if dp==443 and socket.inet_ntoa(b[30:34])==LOCAL and len(p)>=43 and p[0]==22 and p[5]==1 and p[11:43].hex()==marker:return socket.inet_ntoa(b[26:30])
 return None
removed=False;armed=False;rollback=None;timer='mnebydns-shared443-revert-'+str(os.getpid())
try:
 table=json.loads(run(['nft','-j','-a','list','table',FAMILY,TABLE]));client=marker_seen(TRIGGER,START+10);assert client,'controlled trigger absent; nothing changed'
 matches=[]
 for row in table['nftables']:
  r=row.get('rule',{});source=None;dnat=None;port=None
  for e in r.get('expr',[]):
   m=e.get('match',{});left=m.get('left',{}).get('payload',{}) if isinstance(m.get('left'),dict) else {}
   if left.get('protocol')=='ip' and left.get('field')=='saddr':source=m.get('right')
   if left.get('protocol')=='tcp' and left.get('field')=='dport':port=m.get('right')
   if 'dnat' in e:dnat=e['dnat']
  if source==client and port==443 and dnat and dnat.get('port')==18443:matches.append(r)
 OUT['intercepts_controlled_client']=bool(matches);OUT['matching_rules']=len(matches)
 if not matches:
  OUT['done']=True;OUT['changed']=False;print(json.dumps(OUT));raise SystemExit(0)
 assert len(matches)==1,'ambiguous interception; refuse mutation'
 r=matches[0];root=pathlib.Path('/var/backups/mnebydns-shared443-repair-20261116-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S'));root.mkdir(parents=True,mode=0o700)
 (root/'original-table.json').write_text(json.dumps(table));(root/'original-table.json').chmod(0o600)
 restore={k:v for k,v in r.items() if k not in ['handle','index','position']};restore_json={'nftables':[{'insert':{'rule':restore}}]};(root/'restore-rule.json').write_text(json.dumps(restore_json));(root/'restore-rule.json').chmod(0o600)
 rollback=root/'rollback.sh';rollback.write_text('#!/bin/bash\nset -eu\nnft -j -f '+str(root/'restore-rule.json')+'\n');rollback.chmod(0o700)
 run(['nft','-c','-j','-f',str(root/'restore-rule.json')])
 run(['systemd-run','--quiet','--unit='+timer,'--on-active=4m','bash',str(rollback)]);armed=True
 OUT['backup']=str(root);OUT['removed_rule']={'table':TABLE,'chain':r['chain'],'original_port':443,'translated_port':18443,'source':'controlled client only'}
 run(['nft','delete','rule',FAMILY,TABLE,r['chain'],'handle',str(r['handle'])]);removed=True;OUT['stage_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 confirmed=marker_seen(CONFIRM,START+36)
 if confirmed!=client:
  run(['bash',str(rollback)]);removed=False;run(['systemctl','stop',timer+'.timer']);armed=False
  OUT.update(done=True,changed=False,restored=True,reason='client did not confirm improved handshake')
 else:
  run(['systemctl','stop',timer+'.timer']);armed=False;OUT.update(done=True,changed=True,client_verified=True)
  # Persist removal of this exact bad interception across an automatic canary restart.
  # Existing test services are left running; only the shared-port rule was removed.
 print(json.dumps(OUT))
except SystemExit:raise
except Exception as e:
 OUT['error']=str(e)
 if removed and rollback:
  try:run(['bash',str(rollback)]);OUT['restored']=True
  except:OUT['restored']=False
 if armed and OUT.get('restored'):run(['systemctl','stop',timer+'.timer'])
 print(json.dumps(OUT));raise SystemExit(1)
finally:s.close()
