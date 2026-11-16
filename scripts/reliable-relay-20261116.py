#!/usr/bin/env python3
"""Authenticated parallel reliable underlay; gate activation, preserve UDP rollback."""
import concurrent.futures,datetime,hashlib,importlib.util,json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path('/opt/mnebyvpn/reliable-relay-20261116');ROLE=sys.argv[2];assert ROLE in ['DE','RU']
spec=importlib.util.spec_from_file_location('perf','/opt/mnebyvpn/perf-trial-20261116/perf.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
p.ROOT=ROOT;p.STATE=ROOT/('state-'+ROLE+'.json');p.PORT=18905;p.N=8*1024*1024
UNIT='mneby-reliable-relay';TIMER=UNIT+'-rollback';BIN=pathlib.Path('/usr/local/libexec/mneby-wstunnel-11.1.0');CFG=pathlib.Path('/etc/amnezia/amneziawg/tg-relay.conf');AWG=str(p.BIN/'awg');QUICK=str(p.BIN/'awg-quick');IFACE='mn-perf-tls';TRIAL=ROOT/(IFACE+'.conf')
def run(a,timeout=25,check=True):return p.run(a,timeout,check)
def put(path,text):pathlib.Path(path).write_text(text);os.chmod(path,0o600)
def read():return json.loads(p.STATE.read_text())
def save(s):p.save(p.STATE,s)
def timer():
 deadline=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S UTC')
 put('/etc/systemd/system/'+TIMER+'.service','[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(ROOT/'relay.py')+' rollback '+ROLE+'\n')
 put('/etc/systemd/system/'+TIMER+'.timer','[Timer]\nOnCalendar='+deadline+'\nPersistent=true\n[Install]\nWantedBy=timers.target\n');run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',TIMER+'.timer'])
def cert():
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 if p.STATE.exists():raise RuntimeError('Existing reliable trial state')
 if BIN.exists() or run(['ip','link','show',IFACE],check=False).returncode==0:raise RuntimeError('Reserved resource exists')
 for port in [41643,46784,46785,46783,46786,18905]:
  if re.search(r':'+str(port)+r'\s',run(['ss','-Hlntu']).stdout):raise RuntimeError('Reserved port occupied')
 for key in ['ca','leaf']:
  args=['openssl','req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=mneby-relay-'+ROLE+('-ca' if key=='ca' else ''),'-keyout',str(ROOT/(key+'.key')),'-out',str(ROOT/(key+'.pem'))]
  if key=='ca':args+=['-x509','-days','3650','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign']
  run(args)
 put(ROOT/'ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage='+('serverAuth' if ROLE=='DE' else 'clientAuth')+'\nsubjectAltName=DNS:interserver.mnebyvpn.invalid\n')
 run(['openssl','x509','-req','-in',str(ROOT/'leaf.pem'),'-CA',str(ROOT/'ca.pem'),'-CAkey',str(ROOT/'ca.key'),'-CAcreateserial','-days','365','-extfile',str(ROOT/'ext'),'-out',str(ROOT/'cert.pem')])
 for f in ROOT.glob('*.key'):os.chmod(f,0o600)
 print((ROOT/'ca.pem').read_text())
def firewall():
 s=read()
 if ROLE=='DE':
  for rule in [['-p','tcp','--dport','41643','!','-s',p.OTHER+'/32','-m','comment','--comment',UNIT,'-j','REJECT'],['-s',p.OTHER+'/32','-p','tcp','--dport','41643','-m','comment','--comment',UNIT,'-j','ACCEPT']]:
   if run(['iptables','-w','5','-C','INPUT']+rule,check=False).returncode:
    s['rules'].append(rule);save(s);run(['iptables','-w','5','-I','INPUT','1']+rule)
 else:
  rule=['-s',p.OTHER+'/32','-p','udp','--dport','46786','-m','comment','--comment',UNIT,'-j','ACCEPT']
  if run(['iptables','-w','5','-C','INPUT']+rule,check=False).returncode:s['rules'].append(rule);save(s);run(['iptables','-w','5','-I','INPUT','1']+rule)
def stage():
 if not (ROOT/'peer.pem').exists():raise RuntimeError('Peer CA missing')
 raw=(ROOT/'release.tar.gz').read_bytes()
 if hashlib.sha256(raw).hexdigest()!='512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23':raise RuntimeError('Binary pin mismatch')
 import tarfile
 with tarfile.open(ROOT/'release.tar.gz') as t:
  data=t.extractfile('wstunnel').read()
 BIN.parent.mkdir(exist_ok=True,parents=True);BIN.write_bytes(data);BIN.chmod(0o755)
 s={'role':ROLE,'rules':[],'available':{'current':'10.66.77.'+p.LOCAL,'reliable':'10.66.90.'+p.LOCAL}};save(s);timer()
 c=p.config(CFG)
 if c['Interface']['ListenPort']!=('56783' if ROLE=='DE' else '56784'):raise RuntimeError('Unexpected active AWG port')
 lines=['[Interface]','PrivateKey = '+c['Interface']['PrivateKey'],'ListenPort = '+('46783' if ROLE=='DE' else '46786'),'Address = 10.66.90.'+p.LOCAL+'/30','MTU = 1280','Table = off']
 if run(['ip','route','show','10.66.90.0/30']).stdout.strip():raise RuntimeError('Trial subnet occupied')
 allow=['Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','HeaderProtectionKey','ContentPaddingAddition','RandomTrailers']
 lines += [k+' = '+c['Interface'][k] for k in allow if k in c['Interface']]
 lines += ['[Peer]','PublicKey = '+c['Peer']['PublicKey'],'AllowedIPs = 10.66.90.'+p.PEER+'/32','Endpoint = '+(p.OTHER+':46786' if ROLE=='DE' else '127.0.0.1:46784'),'PersistentKeepalive = 5']
 if 'PresharedKey' in c['Peer']:lines+=['PresharedKey = '+c['Peer']['PresharedKey']]
 put(TRIAL,'\n'.join(lines)+'\n')
 firewall()
 for mode,ip in s['available'].items():
  rule=['-i','tg-relay' if mode=='current' else IFACE,'-s',ip.rsplit('.',1)[0]+'.'+p.PEER+'/32','-d',ip+'/32','-p','tcp','--dport','18905','-m','comment','--comment',UNIT+'-bench','-j','ACCEPT'];s=read();s['rules'].append(rule);save(s);run(['iptables','-w','5','-I','INPUT','1']+rule)
 env=dict(os.environ,PATH=str(p.BIN)+':'+os.environ['PATH'],WG_QUICK_USERSPACE_IMPLEMENTATION=str(p.BIN/'amneziawg-go'))
 q=subprocess.run([QUICK,'up',str(TRIAL)],env=env,capture_output=True,timeout=30)
 if q.returncode:raise RuntimeError('Trial interface startup failed')
 creds=' --tls-certificate %d/cert.pem --tls-private-key %d/leaf.key'
 if ROLE=='DE':command='server'+creds+' --tls-client-ca-certs %d/peer.pem --restrict-to 127.0.0.1:46783 --restrict-to 127.0.0.1:'+c['Interface']['ListenPort']+' wss://0.0.0.0:41643'
 else:command='client'+creds+' --tls-verify-certificate --tls-sni-override interserver.mnebyvpn.invalid --connection-retry-max-backoff 5s --websocket-ping-frequency 10s -L udp://127.0.0.1:46784:127.0.0.1:46783?timeout_sec=0 -L udp://127.0.0.1:46785:127.0.0.1:56783?timeout_sec=0 wss://89.125.90.101:41643'
 unit='[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nDynamicUser=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestart=always\nRestartSec=2\nMemoryMax=256M\nTasksMax=64\nRuntimeDirectory='+UNIT+'\nEnvironment=NO_COLOR=true\nEnvironment=SSL_CERT_FILE=%d/peer.pem\nEnvironment=SSL_CERT_DIR=/run/'+UNIT+'\n'
 for f in ['cert.pem','leaf.key','peer.pem']:unit+='LoadCredential='+f+':'+str(ROOT/f)+'\n'
 unit+='ExecStartPre=+/usr/bin/python3 '+str(ROOT/'relay.py')+' firewall '+ROLE+'\nExecStart='+str(BIN)+' '+command.replace(' --tls-certificate',' --log-lvl WARN --nb-worker-threads 2 --tls-certificate',1)+'\n[Install]\nWantedBy=multi-user.target\n'
 put('/etc/systemd/system/'+UNIT+'.service',unit);run(['systemctl','daemon-reload']);run(['systemctl','start',UNIT+'.service'])
 out=open(ROOT/'bench.log','w');proc=subprocess.Popen([sys.executable,str(ROOT/'relay.py'),'serve',ROLE],stdout=out,stderr=out,start_new_session=True);s=read();s['server_pid']=proc.pid;save(s)
 print(json.dumps({'staged':ROLE}))
def measure():
 time.sleep(2)
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:r=dict(pool.map(p.ping,read()['available'].items()))
 print(json.dumps(r))
def endpoint(address):
 key=p.config(CFG)['Peer']['PublicKey'];run([AWG,'set','tg-relay','peer',key,'endpoint',address])
def promote():
 if ROLE=='RU':
  if (ROOT/'original.conf').exists():raise RuntimeError('Original backup exists')
  put(ROOT/'original.conf',CFG.read_text());endpoint('127.0.0.1:46785')
 print(json.dumps({'trial_switch':ROLE}))
def commit():
 if ROLE=='RU':
  old=(ROOT/'original.conf').read_text();text,n=re.subn(r'(?m)^Endpoint\s*=.*$','Endpoint = 127.0.0.1:46785',old)
  if n!=1:raise RuntimeError('Endpoint context mismatch')
  put(CFG,text)
  watch='[Unit]\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(ROOT/'relay.py')+' health RU\n'
  put('/etc/systemd/system/'+UNIT+'-health.service',watch);put('/etc/systemd/system/'+UNIT+'-health.timer','[Timer]\nOnBootSec=60\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n')
 drop=pathlib.Path('/etc/systemd/system/mneby-awg-tg-relay.service.d');drop.mkdir(exist_ok=True);put(drop/'reliable-relay.conf','[Unit]\nWants='+UNIT+'.service\nAfter='+UNIT+'.service\n')
 put(ROOT/'COMMITTED',datetime.datetime.now(datetime.timezone.utc).isoformat());run(['systemctl','daemon-reload']);run(['systemctl','enable',UNIT+'.service']);run(['systemctl','disable','--now',TIMER+'.timer'])
 if ROLE=='RU':run(['systemctl','enable','--now',UNIT+'-health.timer'])
 print(json.dumps({'committed':ROLE}))
def health():
 if ROLE!='RU' or not (ROOT/'COMMITTED').exists() or (ROOT/'FALLBACK').exists():return
 q=run(['ping','-n','-q','-c','4','-i','1','-W','2','-w','8','10.66.77.1'],12,False)
 m=re.search(r'(\d+) received',q.stdout)
 if m and int(m[1])>0:return
 old=ROOT/'original.conf'
 if old.exists():put(CFG,old.read_text());endpoint(p.config(old)['Peer']['Endpoint']);put(ROOT/'FALLBACK','Health check reverted to original UDP endpoint\n')
def cleanup():
 if not p.STATE.exists():return
 s=read();pid=s.get('server_pid')
 if pid:
  proc=pathlib.Path('/proc')/str(pid)/'cmdline'
  if proc.exists() and str(ROOT/'relay.py').encode() in proc.read_bytes():
   import signal
   try:os.kill(pid,signal.SIGTERM)
   except ProcessLookupError:pass
 if TRIAL.exists():
  env=dict(os.environ,PATH=str(p.BIN)+':'+os.environ['PATH'],WG_QUICK_USERSPACE_IMPLEMENTATION=str(p.BIN/'amneziawg-go'));subprocess.run([QUICK,'down',str(TRIAL)],env=env,capture_output=True,timeout=30);TRIAL.unlink(missing_ok=True)
 committed=(ROOT/'COMMITTED').exists()
 for rule in reversed(s['rules']):
  if committed and UNIT+'-bench' not in rule:continue
  if run(['iptables','-w','5','-C','INPUT']+rule,check=False).returncode==0:run(['iptables','-w','5','-D','INPUT']+rule)
 if not committed:run(['systemctl','disable','--now',UNIT+'.service'],check=False)
 print(json.dumps({'cleanup':ROLE,'production_reliable':committed}))
def rollback():
 if (ROOT/'COMMITTED').exists():cleanup();return
 if ROLE=='RU' and (ROOT/'original.conf').exists():
  old=ROOT/'original.conf';put(CFG,old.read_text());endpoint(p.config(old)['Peer']['Endpoint'])
 cleanup();run(['systemctl','disable','--now',TIMER+'.timer'],check=False)
 print(json.dumps({'rollback':ROLE}))
if __name__=='__main__':
 assert os.geteuid()==0
 mode=sys.argv[1]
 if mode=='serve':p.serve()
 elif mode=='bench':p.bench()
 elif mode=='firewall':firewall()
 elif mode=='cert':cert()
 elif mode=='stage':stage()
 elif mode=='measure':measure()
 elif mode=='promote':promote()
 elif mode=='commit':commit()
 elif mode=='health':health()
 elif mode=='cleanup':cleanup()
 elif mode=='rollback':rollback()
 elif mode=='results':
  print(json.dumps({f.name:json.loads(f.read_text()) for f in ROOT.glob('tcp-server-*.json')}))
 else:raise SystemExit('Unknown operation')
