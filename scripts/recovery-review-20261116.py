#!/usr/bin/env python3
"""Bounded, read-only service/config snapshot. Never export credentials or client logs."""
import collections, datetime, hashlib, json, pathlib, re, subprocess, sys

role=sys.argv[1]
out={'role':role,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def run(args,timeout=12):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return p.stdout
    except Exception as e:return 'UNAVAILABLE:'+type(e).__name__
def clean(s):
    s=re.sub(r'\b[a-z0-9]{12}\.dns\.mnebyvpn\.site','<personal>.dns.mnebyvpn.site',s)
    s=re.sub(r'\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b','<uuid>',s,flags=re.I)
    return s
out['load']=run(['uptime']).strip()
out['memory']=run(['free','-m'])
services=[]
for line in run(['systemctl','list-units','--all','--type=service','--no-legend','--plain']).splitlines():
    name=line.split()[0] if line.split() else ''
    if name.startswith(('mnebydns','mneby-awg','wg-quick@','telemt')) or name in ['nginx.service','xray.service']:
        services.append(name)
out['services']={}
for name in services:
    props=run(['systemctl','show',name,'-p','ActiveState,SubState,NRestarts,ExecMainStartTimestamp,MemoryCurrent,TasksCurrent'])
    logs=run(['journalctl','-u',name,'--since','2 hours ago','-n','3000','-o','cat','--no-pager'])
    patterns=['permission denied','timed out','timeout','connection refused','no live upstream','worker_connections','too many open files','traceback','failed','servfail']
    out['services'][name]={'props':dict(x.split('=',1) for x in props.splitlines() if '=' in x),
        'errors':{p:logs.lower().count(p) for p in patterns}}
out['configs']={}
for name in ['/opt/mnebydns-dot/Corefile','/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/etc/mnebydns/personal-sni/nginx.conf']:
    p=pathlib.Path(name)
    if p.is_file():
        raw=p.read_bytes();src=raw.decode(errors='replace')
        # Do not copy raw configs: only routing directives and DNS templates.
        selected=[clean(l) for l in src.splitlines() if re.search(r'googlevideo|youtube|dns\.mnebyvpn|8856|8857|1853|853|10\.66\.77|worker_connections|proxy_(connect_)?timeout|resolver |template IN|forward |tls_servername|^\s*listen ',l)]
        out['configs'][name]={'sha256':hashlib.sha256(raw).hexdigest(),'mode':oct(p.stat().st_mode&0o7777),'lines':selected}
out['containers']=[]
names=run(['docker','ps','--format','{{.Names}}']).splitlines()
for name in names:
    if not name.startswith('mnebyvpn') and 'personal-dot' not in name:continue
    try:d=json.loads(run(['docker','inspect',name]))[0]
    except Exception:continue
    env=dict(x.split('=',1) for x in d['Config'].get('Env',[]) if '=' in x)
    out['containers'].append({'name':name,'image':d['Config']['Image'],'state':d['State']['Status'],
        'restart_count':d['RestartCount'],'mounts':[{'src':m['Source'],'dst':m['Destination']} for m in d.get('Mounts',[])],
        'dns_admin_configured':bool(env.get('DNS_ADMIN_TELEGRAM_ID') or env.get('SUPPORT_TELEGRAM_OPERATOR_ID')),
        'personal_enabled':env.get('MNEBYDNS_PERSONAL_DOT_ENABLED')=='yes'})
out['safe_deploy']=run(['python3','/opt/mnebydns-maintenance/mnebydns_safe_deploy.py','status'],15) if role=='DE' else None
out['checkpoints']={}
for folder in ['/var/lib/mnebydns-safe-deploy','/opt/mnebydns-maintenance','/opt/mnebydns-nov8-restore-20261116']:
    p=pathlib.Path(folder)
    if p.is_dir():out['checkpoints'][folder]=sorted(x.name for x in p.iterdir())[:70]
out['private_ip']=run(['ip','-j','-s','link','show','dev','tg-relay'])
out['ping']=run(['ping','-n','-c','20','-i','0.1','-W','1','-s','1200','10.66.77.'+('2' if role=='DE' else '1')],30)
out['done']=True
print(json.dumps(out))
