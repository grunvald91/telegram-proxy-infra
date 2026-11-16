#!/usr/bin/env python3
"""Read-only public website route, proxy, and upstream diagnostics.
No cookies, credentials, customer IPs or raw logs are printed.
"""
import collections
import pathlib
import re
import socket
import subprocess

HOST='mnebyvpn.site'
ROUTES=('/', '/api/plans','/api/auth/options','/app.js','/journey.js','/landing-art.html','/healthz')
UPSTREAM='http://127.0.0.1:8792'
PUBLIC='https://mnebyvpn.site'

def probe(label,url,family=None):
    args=['curl','-sS','--max-time','9','--connect-timeout','4','--retry','0',
          '-o','/dev/null','-w','%{http_code}|%{time_total}|%{remote_ip}|%{content_type}']
    if family:args.append(family)
    args.append(url)
    try:
        cp=subprocess.run(args,capture_output=True,text=True,timeout=11)
        v=cp.stdout.strip().split('|')
        status=v[0][:3] if v else '000'
        remote=v[2] if len(v)>2 else ''
        iptype='v6' if ':' in remote else 'v4' if remote else 'none'
        duration=v[1] if len(v)>1 else '-'
        mime=v[3].split(';')[0] if len(v)>3 else '-'
        print(f'route_{label}_http={status} rc={cp.returncode} family={iptype} seconds={duration} mime={mime}')
    except Exception as exc:
        print(f'route_{label}_error={type(exc).__name__}')

def show_dns():
    try:
        addrs=sorted({(i[0],i[4][0]) for i in socket.getaddrinfo(HOST,443,type=socket.SOCK_STREAM)})
        print('dns_v4_addresses='+','.join(addr for fam,addr in addrs if fam==socket.AF_INET))
        print('dns_v6_count='+str(sum(fam==socket.AF_INET6 for fam,_ in addrs)))
    except Exception as exc:
        print('dns_error='+type(exc).__name__)

show_dns()
for prefix,origin in [('local',UPSTREAM),('public',PUBLIC)]:
    for path in ROUTES:
        label=path.strip('/').replace('/','_') or 'home'
        probe(f'{prefix}_{label}',origin+path)
# One IPv6-only probe exposes a broken AAAA destination without disclosing credentials.
for path in ('/api/plans','/api/auth/options'):
    probe('public_ipv6_'+path.rsplit('/',1)[-1],PUBLIC+path,'-6')

print('nginx_service='+str(subprocess.run(['systemctl','is-active','nginx'],
    capture_output=True,text=True,timeout=4).stdout.strip()))
try:
    ps=subprocess.run(['docker','ps','--format','{{.Names}}:{{.Status}}'],
        capture_output=True,text=True,timeout=7)
    for name in ps.stdout.splitlines():
        n=name.split(':',1)[0]
        if re.search('mnebyvpn|postgres',n,re.I):
            print('container_'+re.sub('[^A-Za-z0-9_-]','',n)+'='+('running' if 'Up ' in name else 'unknown'))
except Exception as exc:
    print('container_state_error='+type(exc).__name__)

# Only aggregate HTTP statuses by known public routes; never output client addresses.
matches=collections.Counter()
status_codes=collections.Counter()
for path in [pathlib.Path('/var/log/nginx/access.log'),*pathlib.Path('/var/log/nginx').glob('*access*.log')]:
    if not path.is_file() or path.suffix=='.gz':
        continue
    try:
        with path.open(errors='replace') as f:
            for line in collections.deque(f,maxlen=12000):
                m=re.search(r'"(?:GET|HEAD|POST)\s+(/(?:api/plans|api/auth/options|app\.js|journey\.js|landing-art\.html)(?:\?[^ ]*)?)\s+HTTP/[^"]+"\s+(\d{3})\s',line)
                if m:
                    endpoint=m.group(1).split('?',1)[0]
                    code=m.group(2)
                    matches[(endpoint,code)]+=1
                    status_codes[code]+=1
    except OSError:
        pass
for (endpoint,code),count in sorted(matches.items()):
    print(f'edge_log_{endpoint.strip("/").replace("/","_")}_{code}={count}')
print('edge_log_status_counts='+','.join(f'{k}:{v}' for k,v in sorted(status_codes.items())))
# Count common reverse proxy errors without echoing raw log lines.
errtypes=collections.Counter()
for f in pathlib.Path('/var/log/nginx').glob('*error*.log'):
    if not f.is_file():
        continue
    try:
        with f.open(errors='replace') as stream:
            for line in collections.deque(stream,maxlen=1500):
                for tag,pattern in [('upstream_timeout','upstream timed out'),
                                    ('upstream_refused','connect() failed'),
                                    ('upstream_closed','upstream prematurely closed'),
                                    ('tls_handshake','SSL_do_handshake() failed')]:
                    if pattern in line:errtypes[tag]+=1
    except OSError:
        pass
print('nginx_error_categories='+','.join(f'{k}:{v}' for k,v in sorted(errtypes.items())))
print('production_changed=false')
