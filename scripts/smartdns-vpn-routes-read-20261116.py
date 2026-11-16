import pathlib,subprocess,json,re,datetime,sys
ROLE=sys.argv[1];out={'role':ROLE,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def run(a):
 try:
  p=subprocess.run(a,capture_output=True,text=True,timeout=12);return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[-200:]}
 except Exception as e:return {'error':type(e).__name__}
u=run(['systemctl','show','xray.service','-p','ExecStart','-p','ActiveState','-p','MainPID','-p','ExecMainStartTimestamp']);out['service_state']=[l for l in u.get('stdout','').splitlines() if not l.startswith('ExecStart=')]
paths=set(re.findall(r'(/[^ ;]+[.]json)',u.get('stdout','')))
for name in ['/usr/local/etc/xray/config.json','/etc/xray/config.json']:
 if pathlib.Path(name).is_file():paths.add(name)
out['configs']=[]
for name in sorted(paths):
 p=pathlib.Path(name)
 if not p.is_file():continue
 try:c=json.loads(p.read_text())
 except Exception:continue
 item={'path':name,'routing':c.get('routing'),'dns':{k:v for k,v in c.get('dns',{}).items() if k in ['queryStrategy','disableCache','disableFallback','disableFallbackIfMatch']},'inbounds':[],'outbounds':[]}
 for i in c.get('inbounds',[]):
  stream=i.get('streamSettings',{});item['inbounds'].append({k:v for k,v in i.items() if k in ['tag','protocol','listen','port','sniffing']}|{'transport':stream.get('network'),'security':stream.get('security'),'sockopt':stream.get('sockopt')})
 for o in c.get('outbounds',[]):
  settings=o.get('settings',{});v={k:z for k,z in o.items() if k in ['tag','protocol','sendThrough','proxySettings','mux']};v['domainStrategy']=settings.get('domainStrategy');v['targets']=[{k:z for k,z in s.items() if k in ['address','port']} for s in settings.get('servers',[])+settings.get('vnext',[])];v['sockopt']=o.get('streamSettings',{}).get('sockopt');item['outbounds'].append(v)
 out['configs'].append(item)
out['meta_tables']=run(['nft','list','tables']);out['ip_rules']=run(['ip','rule','show']);out['route100']=run(['ip','route','show','table','100']);out['route77']=run(['ip','route','show','table','77'])
lines=run(['journalctl','-u','xray.service','--since','30 minutes ago','-o','cat','--no-pager']).get('stdout','').splitlines();out['xray_error_categories']={word:sum(word in l.lower() for l in lines) for word in ['failed','timeout','reset','rejected','udp','googlevideo','no route','network unreachable']}
out['done']=True
text=json.dumps(out)
# No UUIDs, passwords, Reality keys or client identities are included.
text=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',lambda m:m[0] if m[0] in ['89.125.90.101','188.120.254.223','10.66.77.1','10.66.77.2','127.0.0.1','0.0.0.0','9.9.9.9','1.1.1.1'] else '<ip>',text)
print(text)
