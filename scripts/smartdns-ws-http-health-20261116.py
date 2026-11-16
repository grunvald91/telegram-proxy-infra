"""Read installed public WS HTTP configuration, capacity and error aggregates.
Never output headers containing credentials, request URLs, log lines or client IPs.
"""
import collections,datetime,json,os,pathlib,re,subprocess,time
now=datetime.datetime.now(datetime.timezone.utc);out={'utc':now.isoformat(),'production_mutations':False}
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=12);return p.stdout+'\n'+p.stderr
nginx=run(['nginx','-T']);selected=[];section=''
allowed={'worker_processes','worker_rlimit_nofile','worker_connections','multi_accept','keepalive_timeout','keepalive_requests','reset_timedout_connection','client_header_timeout','client_body_timeout','send_timeout','tcp_nodelay','tcp_nopush','ssl_protocols','ssl_ciphers','ssl_session_cache','ssl_session_timeout','ssl_handshake_timeout','ssl_reject_handshake','listen','server_name','proxy_read_timeout','proxy_send_timeout','proxy_connect_timeout','proxy_buffering','proxy_buffers','proxy_buffer_size','proxy_request_buffering','proxy_http_version','proxy_socket_keepalive','limit_conn','limit_req','limit_conn_zone','limit_req_zone','limit_conn_status','limit_req_status','access_log','error_log','resolver'}
logs={'/var/log/nginx/error.log'}
for line in nginx.splitlines():
 if line.startswith('# configuration file '):section=line[21:].rstrip(':')
 m=re.match(r'\s*([a-z_]+)\s+(.+)',line)
 if not m:continue
 key,value=m.groups()
 if key=='error_log':logs.add(value.split()[0].rstrip(';'))
 if key in allowed:selected.append({'file':section,'directive':key,'value':value})
 if key=='location' and '/mnebyvpn-vpn/ws' in value:selected.append({'file':section,'directive':key,'value':'/mnebyvpn-vpn/ws'})
 if key=='proxy_pass' and re.match(r'(?:http|https)://(?:127[.]0[.]0[.]1|10[.]66[.]77[.]\d+):\d+/?;',value):selected.append({'file':section,'directive':key,'value':value})
out['nginx_directives']=selected
out['service']=run(['systemctl','show','nginx.service','-p','MainPID','-p','LimitNOFILE','-p','TasksCurrent','-p','MemoryCurrent','-p','MemoryMax','-p','CPUQuotaPerSecUSec','-p','ActiveState'])
out['workers']=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  if (p/'comm').read_text().strip()!='nginx':continue
  status=(p/'status').read_text();fields={k:v.strip() for k,v in (x.split(':',1) for x in status.splitlines() if ':' in x) if k in ['PPid','Uid','VmRSS','Threads']};fields['pid']=int(p.name);fields['fds']=len(list((p/'fd').iterdir()));fields['cgroup']=(p/'cgroup').read_text().strip();fields['open_files_limits']=[l.strip() for l in (p/'limits').read_text().splitlines() if l.startswith('Max open files')];out['workers'].append(fields)
 except OSError:pass
categories=['worker_connections are not enough','too many open files','upstream timed out','SSL_do_handshake() failed','peer closed connection in SSL handshake','limiting connections','limiting requests','upstream prematurely closed connection','no live upstreams','connect() failed','client prematurely closed','recv() failed','send() failed','broken pipe','connection reset by peer']
out['error_aggregates']=[];cut=now.replace(tzinfo=None)-datetime.timedelta(minutes=30)
for name in sorted(logs):
 p=pathlib.Path(name)
 if not p.is_file():continue
 try:
  with p.open('rb') as f:
   f.seek(max(0,p.stat().st_size-2**20));text=f.read().decode(errors='replace')
  counts=collections.Counter();total=0;times=[]
  for line in text.splitlines():
   try:t=datetime.datetime.strptime(line[:19],'%Y/%m/%d %H:%M:%S')
   except ValueError:continue
   if t<cut:continue
   total+=1;times.append(t.isoformat())
   for category in categories:
    if category.lower() in line.lower():counts[category]+=1
  out['error_aggregates'].append({'file':name,'lines_in_last_30_minutes':total,'categories':dict(counts),'first':min(times) if times else None,'last':max(times) if times else None})
 except OSError:pass
connections=run(['ss','-tinH','sport = :8443']);salt=os.urandom(16)
import hashlib
def anonymous(m):
 ip=m[0]
 if ip in ['89.125.90.101','188.120.254.223','127.0.0.1','0.0.0.0','10.66.77.1','10.66.77.2']:return ip
 return '<peer-'+hashlib.sha256(salt+ip.encode()).hexdigest()[:8]+'>'
out['ws_tcp_info']=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',anonymous,connections)
out['done']=True
print(json.dumps(out))
