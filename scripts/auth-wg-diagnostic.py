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
for base in ('/usr/local/sbin','/opt'):
 for p in pathlib.Path(base).rglob('*'):
  try:
   if not p.is_file() or p.stat().st_size>200000 or p.suffix not in ('.py','.sh',''):continue
   if not re.search('monitor|health|watch|keepalive',p.name,re.I):continue
   s=p.read_text(errors='replace'); lines=s.splitlines()
   if 'handshake' not in s.lower() and 'wg peer' not in s.lower():continue
   emit('monitor_file',str(p))
   idx=set()
   for i,l in enumerate(lines):
    if re.search('handshake|wg peer|wg_peer|wg show|awg show',l,re.I):idx.update(range(max(0,i-6),min(len(lines),i+9)))
   emit('monitor_source',[[i+1,lines[i]] for i in sorted(idx) if not re.search('token|password|secret|api.telegram|chat_id',lines[i],re.I)])
  except (OSError,ValueError):pass
if role=='RU':
 for ip in ('http://127.0.0.1:8792','https://mnebyvpn.site'):
  req=urllib.request.Request(ip+'/api/auth/email/start',data=json.dumps({'email':'yookassa-review@mnebyvpn.site'}).encode(),headers={'Content-Type':'application/json','Origin':'https://mnebyvpn.site'})
  try:
   with urllib.request.urlopen(req,timeout=12) as r:emit('review_start_'+ip,{'http':r.status,'body':json.load(r)})
  except urllib.error.HTTPError as e:emit('review_start_'+ip,{'http':e.code,'body':e.read().decode()[:600]})
