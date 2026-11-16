import subprocess,pathlib,time,json,re,sys,urllib.request,urllib.error
role=sys.argv[1]
def run(args):
 try:return subprocess.run(args,capture_output=True,text=True,timeout=18).stdout
 except Exception as e:return type(e).__name__
def emit(k,v):print(role+'_'+k+'='+json.dumps(v),flush=True)
for tool in ('wg','awg'):
 s=run([tool,'show','tg-relay','latest-handshakes'])
 stamps=[int(l.split()[1]) for l in s.splitlines() if len(l.split())==2 and l.split()[1].isdigit()]
 emit(tool+'_handshake_ages',[int(time.time())-v if v else None for v in stamps])
emit('ping',run(['ping','-n','-q','-c','5','-W','2','10.66.77.'+('1' if role=='RU' else '2')]))
for u in ('wg-quick@tg-relay','awg-quick@tg-relay','nginx'):
 emit(u,run(['systemctl','show',u,'-p','ActiveState,SubState,ExecMainStartTimestamp,NRestarts']))
emit('tunnel_journal',run(['journalctl','-u','wg-quick@tg-relay','-u','awg-quick@tg-relay','--since','2026-11-15 21:00:00 UTC','--no-pager','-o','short-iso'])[-18000:])
units=run(['systemctl','list-units','--all','--no-legend','--plain']).splitlines()
emit('monitor_units',[l for l in units if re.search('monitor|health|watch|keepalive',l,re.I)])

if role=='DE':
 p=pathlib.Path('/usr/local/sbin/proxy-monitor.sh')
 emit('proxy_monitor_source','\n'.join(l for l in p.read_text().splitlines() if not re.search('token|password|secret|api.telegram|chat_id',l,re.I)))
 emit('monitor_cron',run(['crontab','-l']))
 for path in ('/var/log/proxy-monitor.log','/var/lib/proxy-monitor/state','/var/run/proxy-monitor.state','/var/tmp/proxy-monitor.state','/tmp/proxy-monitor.state'):
  p=pathlib.Path(path)
  if p.is_file():emit('monitor_history_'+path,p.read_text()[-9000:])
for size in ('32','1200'):
 emit('ping_extended_'+size,run(['ping','-n','-q','-c','30','-i','0.2','-s',size,'-W','1','10.66.77.'+('1' if role=='RU' else '2')]))
for tool in ('wg','awg'):
 emit(tool+'_keepalive',[[*l.split()[1:]] for l in run([tool,'show','tg-relay','persistent-keepalive']).splitlines()])
if role=='RU':
 import collections
 counts=collections.Counter()
 for p in pathlib.Path('/var/log/nginx').glob('*log*'):
  if not p.is_file() or p.suffix=='.gz':continue
  for l in collections.deque(p.open(errors='replace'),maxlen=30000):
   m=re.search(r'"POST /api/auth/email/(start|verify) HTTP/[^\"]+"\s+(\d{3})',l)
   if m:counts[(m[1],m[2])]+=1
 emit('auth_edge_counts',{str(k):v for k,v in counts.items()})
 logs=run(['docker','logs','--since','2026-11-16T00:00:00+03:00','--tail','500','mnebyvpn-public-web'])
 emit('web_log_categories',dict(collections.Counter(re.findall('permission denied|does not exist|EMAIL_NOT_SENT|EMAIL_RATE_LIMIT|error|Error|timeout',logs))))
