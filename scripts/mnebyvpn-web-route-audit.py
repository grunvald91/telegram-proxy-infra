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
# YuKassa reviewer incident: only read-only presence/permissions and aggregate
# auth status codes. The protected PIN, email, IPs and DB secrets are never logged.
import hashlib
import hmac
import json
import urllib.parse

for path in [pathlib.Path('/var/log/nginx/access.log'), *pathlib.Path('/var/log/nginx').glob('*access*.log')]:
    if not path.is_file() or path.suffix=='.gz':
        continue
    counters=collections.Counter()
    try:
        with path.open(errors='replace') as stream:
            for line in collections.deque(stream,maxlen=15000):
                m=re.search(r'"POST /api/auth/email/(start|verify) HTTP/[^"]+"\s+(\d{3})\s',line)
                if m:counters[(m.group(1),m.group(2))]+=1
    except OSError:
        continue
    for (endpoint,status),count in sorted(counters.items()):
        print(f'reviewer_auth_edge_{endpoint}_{status}={count}')

def safe_db(query):
    result=subprocess.run(['docker','exec','-i','mnebyvpn-stage-postgres','psql',
       '-X','-v','ON_ERROR_STOP=1','-qAt','-U','mnebyvpn_stage','-d','mnebyvpn_stage'],
       input=query,text=True,capture_output=True,timeout=12)
    if result.returncode:
        print('reviewer_db_query_error=true')
        return None
    return result.stdout.strip()

try:
    settings={}
    for line in pathlib.Path('/opt/mnebyvpn/public/web.env').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1)
            settings[key]=value.strip()
    conn=urllib.parse.urlsplit(settings.get('WEB_AUTH_DATABASE_URL',''))
    print('reviewer_auth_db_matches_stage='+str(conn.path=='/mnebyvpn_stage').lower())
    check=safe_db("""
        SELECT exists(SELECT 1 FROM web_review_login WHERE email='yookassa-review@mnebyvpn.site')::int,
               coalesce((SELECT enabled::int FROM web_review_login WHERE email='yookassa-review@mnebyvpn.site'),0),
               coalesce((SELECT failed_attempts FROM web_review_login WHERE email='yookassa-review@mnebyvpn.site'),0),
               coalesce((SELECT (locked_until>clock_timestamp())::int FROM web_review_login WHERE email='yookassa-review@mnebyvpn.site'),0),
               has_table_privilege('mnebyvpn_site_auth','web_review_login','SELECT')::int,
               has_column_privilege('mnebyvpn_site_auth','web_review_login','failed_attempts','UPDATE')::int
    """)
    if check:
        fields=check.split('|')
        print('reviewer_account_present='+str(fields[0]=='1').lower())
        print('reviewer_account_enabled='+str(fields[1]=='1').lower())
        print('reviewer_failed_code_attempts='+fields[2])
        print('reviewer_lock_active='+str(fields[3]=='1').lower())
        print('reviewer_role_select='+str(fields[4]=='1').lower())
        print('reviewer_role_update_counter='+str(fields[5]=='1').lower())
    secret=settings.get('WEB_SESSION_SECRET','')
    if len(secret)>=32:
        identity='yookassa-review@mnebyvpn.site'
        key=('mail-rate:review-start-email:'+identity).encode()
        digest=hmac.new(secret.encode(),key,hashlib.sha256).hexdigest()
        # A freshly provisioned reviewer receives an 8-digit permanent code;
        # the /start endpoint should allow only a bounded number of visits.
        status=safe_db("SELECT attempts, (window_start > clock_timestamp() - interval '60 minutes')::int FROM web_email_rate_limits WHERE subject_hash='"+digest+"'")
        if status:
            attempts,active=status.split('|')
            print('reviewer_start_requests_in_rate_bucket='+attempts)
            print('reviewer_start_rate_window_active='+str(active=='1').lower())
        else:
            print('reviewer_start_requests_in_rate_bucket=0')
except Exception as exc:
    print('reviewer_diagnostic_error='+type(exc).__name__)

print('production_changed=false')
