import subprocess,json,socket,struct,time,pathlib,sys,datetime,re,os
START=1794811892
MARKER='ae4a51f9905ace20c4d1228068de19d0f77744b510c3f39efbc32e4e66b711e4'
COMMENT='smartdns_scoped_nfq_test_20261116'
LOCAL='89.125.90.101'
OUT={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'test':'NFQUEUE scoped bypass for controlled client TCP443','production_files_changed':False}
def run(a,check=True):
 p=subprocess.run(a,capture_output=True,text=True,timeout=12)
 if check and p.returncode:raise RuntimeError('command failed '+a[0]+': '+p.stderr[-300:])
 return p.stdout
def rules():return [x['rule'] for x in json.loads(run(['nft','-j','-a','list','chain','inet','telegram_nfqws','post']))['nftables'] if 'rule' in x]
def cleanup():
 for r in rules():
  if r.get('comment')==COMMENT:run(['nft','delete','rule','inet','telegram_nfqws','post','handle',str(r['handle'])])
 return not any(r.get('comment')==COMMENT for r in rules())
ROOT=pathlib.Path('/run/mnebydns-scoped-nfq-test-20261116');ROOT.mkdir(mode=0o700,exist_ok=True)
rollback=ROOT/'rollback.py';rollback.write_text("import subprocess,json\np=subprocess.run(['nft','-j','-a','list','chain','inet','telegram_nfqws','post'],capture_output=True,text=True)\nif p.returncode==0:\n for x in json.loads(p.stdout)['nftables']:\n  r=x.get('rule',{})\n  if r.get('comment')=='"+COMMENT+"':subprocess.run(['nft','delete','rule','inet','telegram_nfqws','post','handle',str(r['handle'])],check=True)\n")
timer='mnebydns-scoped-nfq-revert-20261116-'+str(os.getpid());armed=False
try:
 arr=rules();assert not any(r.get('comment')==COMMENT for r in arr),'prior scoped test still active'
 OUT['queue_active']=any(any('queue' in e for e in r.get('expr',[])) for r in arr);assert OUT['queue_active'],'queue absent'
 s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.3);client=None
 while time.time()<START+8:
  try:b,addr=s.recvfrom(10000)
  except socket.timeout:continue
  if addr[0]=='lo' or len(b)<90 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
  off=14+(b[14]&15)*4
  if len(b)<off+20:continue
  sp,dp=struct.unpack('!HH',b[off:off+4]);p=b[off+(b[off+12]>>4)*4:]
  if dp==443 and socket.inet_ntoa(b[30:34])==LOCAL and len(p)>=43 and p[0]==22 and p[5]==1 and p[11:43].hex()==MARKER:client=socket.inet_ntoa(b[26:30]);break
 s.close();assert client,'controlled trigger not observed; no rules changed'
 # Validate narrowly scoped rule before arming and insertion.
 args=['nft','insert','rule','inet','telegram_nfqws','post','ip','daddr',client,'tcp','sport','443','counter','accept','comment',COMMENT]
 run(['nft','-c',*args[1:]])
 run(['systemd-run','--quiet','--unit='+timer,'--on-active=90s','/usr/bin/python3',str(rollback)]);armed=True
 run(args);OUT['bypass_enabled_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 while time.time()<START+30:time.sleep(.25)
 r=next(r for r in rules() if r.get('comment')==COMMENT);OUT['bypass_counters']=[e['counter'] for e in r.get('expr',[]) if 'counter' in e]
 OUT['bypass_rule_first']=rules()[0].get('comment')==COMMENT
 OUT['restored']=cleanup();run(['systemctl','stop',timer+'.timer']);armed=False
 conf=pathlib.Path('/etc/zapret2/telegram-nfqws.conf');OUT['nfqws_config']=conf.read_text() if conf.exists() else None
 lua=pathlib.Path('/opt/zapret2/lua/zapret-antidpi.lua')
 if lua.exists():
  lines=lua.read_text().splitlines();idx=next((i for i,l in enumerate(lines) if re.search(r'function\s+synack_split\b',l)),None)
  if idx is not None:OUT['synack_split_source']='\n'.join(lines[idx:idx+100])
 OUT['done']=True
except Exception as e:
 OUT['error']=str(e)
 try:OUT['restored']=cleanup()
 except:OUT['restored']=False
 if armed and OUT.get('restored'):run(['systemctl','stop',timer+'.timer'],check=False)
 print(json.dumps(OUT));raise SystemExit(1)
print(json.dumps(OUT))
