import concurrent.futures,importlib.util,json,pathlib,time
spec=importlib.util.spec_from_file_location('runner','scripts/perf-trial-runner-20261116.py')
# Reuse only definitions: importing the original would start its previous trial.
source=pathlib.Path(spec.origin).read_text().split('\ntry:\n    with concurrent.futures')[0]
ns={};exec(compile(source,spec.origin,'exec'),ns)
ssh,execute,roles,OUT=ns['ssh'],ns['execute'],ns['roles'],ns['OUT'];ROOT='/opt/mnebyvpn/reliable-relay-20261116'
def call(role,mode,timeout=90):return ssh(role,'python3 '+ROOT+'/relay.py '+mode+' '+role,timeout)
def upload(role):
 ssh(role,'install -d -m 700 '+ROOT)
 for src,dst in [('scripts/reliable-relay-20261116.py','relay.py'),('release.tar.gz','release.tar.gz')]:execute(role,['scp']+ns['opts']+[src,'root@'+roles[role]+':'+ROOT+'/'+dst])
 return role,call(role,'cert')
def bench_dns():
 return json.loads(ssh('RU','docker exec --env-file /opt/mnebyvpn/bot/web.env -e DNS_BENCH_PRIVATE_ONLY=yes -i mnebydns-personal-dot-private node --experimental-strip-types --input-type=module < /opt/mnebyvpn/perf-trial-20261116/dns-bench.mjs',90))
def write(name,value):(OUT/(name+'.json')).write_text(json.dumps(value,indent=2))
committed=False
try:
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:certs=dict(pool.map(upload,roles))
 for role in roles:
  peer='RU' if role=='DE' else 'DE';file=pathlib.Path('peer-'+role+'.pem');file.write_text(certs[peer]);execute(role,['scp']+ns['opts']+[str(file),'root@'+roles[role]+':'+ROOT+'/peer.pem'])
 for role in roles:call(role,'stage')
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:measures=dict(zip(roles,pool.map(lambda role:json.loads(call(role,'measure')),roles)))
 write('parallel-ping',measures)
 speeds=json.loads(call('RU','bench',100));write('parallel-tcp',speeds)
 results={role:json.loads(call(role,'results')) for role in roles};write('server-tcp',results)
 for role,r in measures.items():
  c,t=r['current'],r['reliable']
  if t['sent']!=200 or t['received']!=200 or t['rtt_avg_ms']>max(120,c['rtt_avg_ms']*2):raise RuntimeError('Reliable channel loss/latency gate failed '+role)
 speed={x['mode']:x for x in speeds}
 if not speed['reliable'].get('complete') or speed['reliable']['de_to_ru_mbps']<max(15,speed['current'].get('de_to_ru_mbps',0)*.9):raise RuntimeError('Reliable channel download gate failed')
 up={v['mode']:v for v in results['DE'].values()}
 if not up['reliable'].get('complete') or up['reliable']['ru_to_de_mbps']<15:raise RuntimeError('Reliable channel upload gate failed')
 # Change only RU endpoint at runtime. Persistent config is saved after real DNS succeeds.
 call('RU','promote');time.sleep(2)
 checks={}
 for role in roles:
  out=ssh(role,'ping -n -q -c 100 -i 0.05 -W 1 -w 10 10.66.77.'+('2' if role=='DE' else '1')+' || true',20);checks[role]=out
  if '100 packets transmitted, 100 received' not in out:raise RuntimeError('Active channel validation failed '+role)
 write('active-ping',checks);dns=bench_dns();write('dns-after-reliable',dns)
 row=dns['results'][0]
 if row['errors'] or row['premium']['n']!=10 or row['ordinary']['n']!=10 or row['premium']['p95_ms']>250:raise RuntimeError('Active DNS reliability gate failed')
 for role in roles:call(role,'commit')
 committed=True;print('RELIABLE_RELAY_COMMITTED=true')
finally:
 for role in ['RU','DE']:
  try:print(call(role,'cleanup' if committed else 'rollback',60).strip())
  except Exception as e:print('LOCAL_ROLLBACK_TIMER_PENDING='+role+' '+type(e).__name__)
