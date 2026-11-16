"""Inspect active Nginx configuration and experimental rule without editing."""
import datetime,hashlib,json,pathlib,re,subprocess

def run(a):
 p=subprocess.run(a,capture_output=True,text=True,timeout=15);return p
out={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'production_changed':False,'nginx':[]}
for path in ['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/etc/mnebydns/personal-sni/nginx.conf']:
 p=pathlib.Path(path)
 if not p.is_file():continue
 r=run(['/usr/sbin/nginx','-T','-c',path]);assert r.returncode==0,'nginx -T failed for '+path
 lines=r.stdout.splitlines();matches=[];file=path
 for n,line in enumerate(lines,1):
  if line.startswith('# configuration file '):file=line[len('# configuration file '):].rstrip(':')
  clean=line.strip()
  if clean.startswith('#'):continue
  if re.search(r'(?i)alt-svc|\bhttp3\b|\bquic\b|^quic_',clean):matches.append({'file':file,'directive':clean[:400]})
 out['nginx'].append({'config':path,'syntax_ok':True,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'h3_or_alt_svc_directives':matches,'ssl_preread_enabled':any(re.match(r'\s*ssl_preread\s+on\s*;',x) for x in lines)})
for path in ['/opt/mnebydns-dot/Corefile','/opt/mnebydns-vpn-video-origin-20261116/Corefile']:
 p=pathlib.Path(path)
 if not p.exists():continue
 s=p.read_text();out.setdefault('dns_configs',[]).append({'config':path,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'https_template_count':len(re.findall(r'\btemplate\s+IN\s+HTTPS\b',s)),'svcb_template_count':len(re.findall(r'\btemplate\s+IN\s+SVCB\b',s))})
r=run(['nft','-j','list','table','inet','mnebydns_udp443_owner_exp_20261116'])
out['reject_rule']=json.loads(r.stdout) if r.returncode==0 else {'present':False}
r=run(['systemctl','is-active','mnebydns-udp443-owner-exp-revert-20261116.timer']);out['rollback_timer']=r.stdout.strip()
print(json.dumps(out))
