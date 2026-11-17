#!/usr/bin/env python3
"""Peer-scoped public UDP canary with independent thirty-minute rollback."""
import asyncio,hashlib,importlib.util,ipaddress,json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path(sys.argv[2]).resolve()
if not re.fullmatch(r'/opt/mnebydns-h3-origin-diag-[0-9]+-[0-9]+',str(ROOT)):raise RuntimeError('BAD_ROOT')
TAG='MNEBYDNS_H3_OWNER_CANARY_20261117'
FILES=['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/etc/zapret2/telegram-nfqws.conf','/usr/local/sbin/telegram-foreign-nfqws-rules']
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def cmd(a,check=True):
 p=subprocess.run(a,capture_output=True,text=True,timeout=15)
 if check and p.returncode:raise RuntimeError('COMMAND_FAILED_'+pathlib.Path(a[0]).name+'_'+str(p.returncode))
 return p
def hashes():return {p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in FILES}
def cleanup():
 # Delete only rules carrying our unique comment. Do not touch the TCP-only guard.
 for row in cmd(['iptables','-S','INPUT']).stdout.splitlines():
  if TAG in row:
   import shlex
   args=shlex.split(row);args[0]='-D';cmd(['iptables',*args])
 unit=ROOT.name.replace('h3-origin-diag','h3-canary')
 cmd(['systemctl','stop',unit+'.service'],False)
 cmd(['systemctl','is-active','--quiet','mnebydns-google-tcp-only-20261117.service'])
 if TAG in cmd(['iptables','-S','INPUT']).stdout:raise RuntimeError('CANARY_RULE_LEFT')
 if (ROOT/'hashes.json').exists() and json.loads((ROOT/'hashes.json').read_text())!=hashes():raise RuntimeError('PROTECTED_CONFIG_DRIFT')
 cmd(['systemctl','stop','mnebydns-h3-clean-'+ROOT.name.removeprefix('mnebydns-h3-origin-diag-')+'.timer'],False)
 if ROOT.exists():os.chmod(ROOT,0o700)
 emit('H3_CANARY_REMOVED',True)
 emit('TCP_ONLY_GUARD_STILL_ACTIVE',True)

def apply():
 rows=[json.loads(x) for x in pathlib.Path('/run/mnebydns-normalcurl-44087349813-1/bindings.private.jsonl').read_text().splitlines()]
 expected={'c03b85752da74621':1578,'4e2c3866eb62d91e':234,'da67f0a412cd9bb8':1592}
 matched={x['probe']:x for x in rows if x['probe'] in expected}
 if set(matched)!=set(expected) or any(x['expected']!=expected[k] or not 0<=time.time()-x['observed_at']<=3600 for k,x in matched.items()):raise RuntimeError('STALE_OR_MISSING_PEER_BINDING')
 addresses={x['address'] for x in matched.values()}
 if len(addresses)!=1:raise RuntimeError('AMBIGUOUS_PEER')
 phone=next(iter(addresses));control=os.environ['SSH_CONNECTION'].split()[0]
 peers=sorted({phone,control})
 if any(not ipaddress.ip_address(x).is_global or ipaddress.ip_address(x).version!=4 for x in peers):raise RuntimeError('BAD_PEER')
 cmd(['systemctl','is-active','--quiet','mnebydns-google-tcp-only-20261117.service'])
 cmd(['iptables','-C','INPUT','-d','89.125.90.101/32','-p','udp','--dport','443','-m','comment','--comment','MNEBYDNS_GOOGLE_TCP_ONLY_20261117','-j','REJECT','--reject-with','icmp-port-unreachable'])
 if cmd(['ss','-Hlun','sport = :443']).stdout.strip():raise RuntimeError('UDP443_NOT_FREE')
 if TAG in cmd(['iptables','-S','INPUT']).stdout:raise RuntimeError('EXISTING_CANARY_RULE')
 (ROOT/'hashes.json').write_text(json.dumps(hashes()));(ROOT/'peers.json').write_text(json.dumps(peers));os.chmod(ROOT/'peers.json',0o644)
 os.chmod(ROOT,0o755)
 for name in ['canary.py','relay.py']:os.chmod(ROOT/name,0o644)
 suffix=ROOT.name.removeprefix('mnebydns-h3-origin-diag-');unit='mnebydns-h3-canary-'+suffix
 timer='mnebydns-h3-clean-'+suffix
 # Independent timer is armed BEFORE starting the service or adding accept rules.
 cmd(['systemd-run','--quiet','--collect','--unit='+timer,'--on-active=1800s','/usr/bin/python3','-B',str(ROOT/'canary.py'),'clean',str(ROOT)])
 cmd(['systemctl','is-active','--quiet',timer+'.timer'])
 try:
  cmd(['systemd-run','--quiet','--unit='+unit,'--property=RuntimeMaxSec=1810','--property=User=nobody','--property=Group=nogroup','--property=NoNewPrivileges=yes','--property=AmbientCapabilities=CAP_NET_BIND_SERVICE','--property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateDevices=yes','--property=MemoryMax=128M','--property=CPUQuota=30%','--property=TasksMax=24','--property=StandardOutput=append:'+str(ROOT/'canary.log'),'--property=StandardError=append:'+str(ROOT/'canary.log'),'/usr/bin/env','PYTHONPATH='+str(ROOT/'deps'),'/usr/bin/python3','-B',str(ROOT/'canary.py'),'serve',str(ROOT)])
  for _ in range(25):
   if '89.125.90.101:443' in cmd(['ss','-Hlun','sport = :443']).stdout:break
   time.sleep(.2)
  else:raise RuntimeError('CANARY_NOT_LISTENING')
  for peer in peers:cmd(['iptables','-I','INPUT','1','-d','89.125.90.101/32','-s',peer,'-p','udp','--dport','443','-m','comment','--comment',TAG,'-j','ACCEPT'])
 except BaseException:cleanup();raise
 emit('H3_CANARY_AUTHENTICATED_PHONE_AND_CONTROL',True)
 emit('H3_CANARY_EXPIRES_UTC',time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+1800)))
 emit('H3_CANARY_ACTIVE',True)

async def serve():
 peers=set(json.loads((ROOT/'peers.json').read_text()))
 spec=importlib.util.spec_from_file_location('canary_relay',ROOT/'relay.py');mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
 original_allowed=mod.allowed
 mod.allowed=lambda name: original_allowed(name) and (name in ('youtube.com','googlevideo.com','youtubei.googleapis.com') or name.endswith(('.youtube.com','.googlevideo.com','.ytimg.com','.googleapis.com','.ggpht.com')))
 class Router(mod.YoutubeRouter):
  def datagram_received(self,data,source):
   if source[0] in peers:super().datagram_received(data,source)
 transport,router=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Router('de-public','','89.125.90.101'),local_addr=('89.125.90.101',443))
 try:await asyncio.Event().wait()
 finally:
  emit('H3_FINAL_COUNTERS',router.counters);transport.close()
if __name__=='__main__':
 if sys.argv[1]=='apply':apply()
 elif sys.argv[1]=='clean':cleanup()
 elif sys.argv[1]=='serve':asyncio.run(serve())
 else:raise SystemExit(2)
