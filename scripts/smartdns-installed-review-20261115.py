#!/usr/bin/env python3
"""Read-only live SmartDNS source and aggregate errors. No packet bodies or keys."""
import collections, concurrent.futures, datetime, hashlib, json, os, pathlib, re, socket, ssl, struct, subprocess, sys, time

ROLE = sys.argv[1]
ROOT = pathlib.Path('/')
OUT = {'role': ROLE, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'sources': {}, 'services': {}, 'logs': {}}
NAMES = ['www.youtube.com','youtubei.googleapis.com','rr1---sn-gxuo03g-ig3s.googlevideo.com','speech.googleapis.com','voiceinput.googleapis.com','www.google.com','generativelanguage.googleapis.com','aiplatform.googleapis.com','antigravity.google','antigravity.google.com','daily-cloudcode-pa.googleapis.com','example.org']

def run(args, timeout=12):
    try:
        p = subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, '', type(e).__name__

def clean(s):
    s = re.sub(r'(?<![a-z0-9])[a-z0-9]{12}\.dns\.mnebyvpn\.site', '<personal-id>.dns.mnebyvpn.site', s, flags=re.I)
    s = re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+', r'\1<redacted>', s)
    s = re.sub(r'(?i)(https?://)[^/\s:@]+:[^/\s@]+@', r'\1<redacted>@', s)
    # Never export hardcoded secret assignments; retain environment references.
    lines=[]
    for l in s.splitlines():
        if re.match(r'\s*Environment=',l):
            l = '# REDACTED systemd inline environment'
        if re.search(r'(?i)(password|secret|token|private[_-]?key|api[_-]?key)\s*[=:]\s*["\x27][^"\x27]{12,}["\x27]',l) and not re.search(r'process\.env|os\.environ|\$\{|\$[A-Z_]',l):
            l = '# REDACTED possible secret assignment'
        lines.append(l)
    return '\n'.join(lines) + ('\n' if s.endswith('\n') else '')

def source(path):
    p=pathlib.Path(path)
    if not p.is_file() or p.suffix in ('.pem','.key') or p.stat().st_size > 800000:
        return
    b=p.read_bytes(); text=b.decode('utf-8',errors='replace')
    OUT['sources'][str(p)]={'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'mtime':p.stat().st_mtime,'content':clean(text)}

def category(msg):
    lo=msg.lower()
    for tag in ['too many open files','no buffer space','out of memory','cannot allocate memory','worker_connections are not enough','no live upstreams','host not found','could not be resolved','upstream timed out','connection timed out','connection refused','connection reset by peer','broken pipe','network is unreachable','no route to host','permission denied','invalid quic','traceback','exception','failed','error','warn']:
        if tag in lo:return tag
    return 'other'

rc,text,err=run(['systemctl','list-units','--all','--no-legend','--plain','--type=service'])
units=[]
for l in text.splitlines():
    t=l.split()
    if t and (t[0].startswith('mnebydns') or t[0] in ['nginx.service','xray.service','mnebyvpn-vpn-provisioner.service']):units.append(t[0])
for u in units:
    rc,t,e=run(['systemctl','show',u,'-p','ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,FragmentPath,MemoryCurrent,TasksCurrent,LimitNOFILE,RestrictAddressFamilies'])
    d=dict(l.split('=',1) for l in t.splitlines() if '=' in l)
    OUT['services'][u]=d
    if u.startswith('mnebydns'):
        source(d.get('FragmentPath','/nonexistent'))
        pid=d.get('MainPID','0')
        if pid!='0':
            p=pathlib.Path('/proc')/pid
            try:
                args=[x.decode(errors='replace') for x in (p/'cmdline').read_bytes().split(b'\0') if x]
                d['runtime_source_paths']=[x for x in args if x.startswith(('/opt/mnebydns','/etc/mnebydns','/usr/local/sbin/mnebydns'))]
                d['fd_count']=len(list((p/'fd').iterdir()))
                d['cwd']=str((p/'cwd').resolve())
                for x in d['runtime_source_paths']:source(x)
                for x in ['/opt/mnebydns-dot/Corefile']:
                    v=p/'root'/x.lstrip('/')
                    if v.is_file():d['process_view_'+x]=hashlib.sha256(v.read_bytes()).hexdigest()
            except Exception as ex:d['process_read_error']=type(ex).__name__
    rc,t,e=run(['journalctl','-u',u,'--since','24 hours ago','-n','30000','-o','json','--no-pager'],20)
    count=collections.Counter(); recent=[]; counters=[]; total=0
    for l in t.splitlines():
        try: j=json.loads(l)
        except Exception:continue
        msg=j.get('MESSAGE','')
        if not isinstance(msg,str):continue
        total+=1
        if re.search(r'(?i)error|failed|warn|timeout|refused|traceback|unreachable|broken pipe',msg):
            k=category(msg);count[k]+=1
            recent.append({'ts_us':j.get('__REALTIME_TIMESTAMP'),'category':k})
        if msg.startswith('youtube_quic_') and '_active=' in msg:
            c={k:int(v) for k,v in re.findall(r'([a-z_]+)=(\d+)',msg)}
            if c:counters.append({'ts_us':j.get('__REALTIME_TIMESTAMP'),'counts':c})
    OUT['logs'][u]={'records':total,'bounded_at':30000,'categories':dict(count),'recent_error_categories':recent[-12:],'quic_first_last':counters[:1]+counters[-1:]}

paths=['/opt/mnebydns-dot/Corefile','/etc/mnebydns-googlepilot/nginx.conf','/etc/mnebydns/personal-sni/nginx.conf','/usr/local/sbin/mnebydns-personal-sni-watch','/opt/mnebydns-youtube-quic-43612369808/relay.py','/opt/mnebydns-de89-public-quic-20261115/listener.py','/opt/mnebydns-vpn-dot-selfroute-20261115/manage.sh']
for p in paths:source(p)
# Main nginx config: stream mapping only, retain original line numbers.
p=pathlib.Path('/etc/nginx/nginx.conf')
if p.is_file():
    b=p.read_bytes();lines=b.decode(errors='replace').splitlines();selected=[];inside=False
    for n,l in enumerate(lines,1):
        if 'map $ssl_preread_server_name $direct_mtproxy_backend' in l:inside=True
        if inside:selected.append([n,clean(l).rstrip()])
        if inside and l.strip()=='}':inside=False
    OUT['nginx_map']={'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'lines':selected}
    OUT['nginx_directives']=[[n,clean(l).strip()] for n,l in enumerate(lines,1) if re.search(r'worker_connections|worker_processes|access_log|error_log|resolver |proxy_timeout|proxy_connect_timeout|ssl_preread|listen .*443',l)]

# Error logs are grouped locally. No IPs, URLs, messages, or client identifiers leave the server.
logfiles=set(pathlib.Path('/var/log/nginx').glob('*error*.log'))
for root in ['/var/log/mnebydns','/var/log/mnebydns-googlepilot']:
    if pathlib.Path(root).exists():logfiles.update(pathlib.Path(root).glob('*.log'))
for p in list(logfiles)[:30]:
    rc,t,e=run(['tail','-n','20000',str(p)],12)
    cats=collections.Counter(); stamps=[]; domains=collections.Counter()
    for l in t.splitlines():
        if not re.search(r'\[(?:error|warn|crit|alert|emerg)\]|timed out|failed|refused',l,re.I):continue
        cats[category(l)]+=1
        m=re.match(r'\d{4}/\d\d/\d\d \d\d:\d\d:\d\d',l)
        if m:stamps.append(m.group())
        for h in NAMES:
            if h in l:domains[h]+=1
    OUT['logs'][str(p)]={'tail_lines':len(t.splitlines()),'bounded_at':20000,'categories':dict(cats),'first_last_error_time':stamps[:1]+stamps[-1:],'known_domains_in_errors':dict(domains),'size':p.stat().st_size}

OUT['resources']={'load':os.getloadavg(),'cpus':os.cpu_count(),'memory':{l.split(':')[0]:l.split(':')[1].strip() for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.split(':')[0] in ['MemAvailable','MemTotal','SwapFree','SwapTotal']},'disk':run(['df','-h','/'])[1]}
OUT['limits']={p:pathlib.Path('/proc/sys/'+p).read_text().strip() for p in ['net/netfilter/nf_conntrack_count','net/netfilter/nf_conntrack_max','net/core/rmem_max','net/core/wmem_max'] if pathlib.Path('/proc/sys/'+p).exists()}
OUT['kernel_errors']=run(['journalctl','-k','--since','24 hours ago','-p','warning','-o','cat','--no-pager'],15)[1]
OUT['kernel_errors']=dict(collections.Counter(category(l) for l in OUT['kernel_errors'].splitlines()))
def netstats():
    out={}
    for f in ['/proc/net/snmp','/proc/net/netstat']:
        ls=pathlib.Path(f).read_text().splitlines()
        for h,v in zip(ls[::2],ls[1::2]):
            for k,x in zip(h.split()[1:],v.split()[1:]):
                if re.search(r'Err|Drop|Fail|Retrans|Timeout|Overflow|NoPort|Discards|InDatagrams|OutDatagrams',k):out[h.split()[0].rstrip(':')+'.'+k]=int(x)
    return out
s0=netstats();time.sleep(10);s1=netstats()
OUT['network_counters_10s']={k:v-s0.get(k,0) for k,v in s1.items() if v-s0.get(k,0)}
OUT['network_counters_total']={k:v for k,v in s1.items() if v}

def exact(s,n):
    b=b''
    while len(b)<n:
        v=s.recv(n-len(b))
        if not v:raise EOFError()
        b+=v
    return b
def dns(item):
    h,typ=item;t=time.monotonic()
    q=struct.pack('!HHHHHH',23015,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in h.split('.'))+b'\0'+struct.pack('!HH',typ,1)
    d={'host':h,'type':typ}
    try:
        with socket.create_connection(('89.125.90.101',853),timeout=5) as s:
            with ssl.create_default_context().wrap_socket(s,server_hostname='dns.mnebyvpn.site') as c:
                c.settimeout(5);c.sendall(struct.pack('!H',len(q))+q);a=exact(c,int.from_bytes(exact(c,2),'big'))
        d.update(rcode=a[3]&15,ancount=int.from_bytes(a[6:8],'big'),synthetic_de89=socket.inet_aton('89.125.90.101') in a,synthetic_ru188=socket.inet_aton('188.120.254.223') in a)
    except Exception as ex:d['error']=type(ex).__name__
    d['ms']=round((time.monotonic()-t)*1000);return d
if ROLE=='DE':
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:OUT['dns_probes']=list(pool.map(dns,[(h,k) for h in NAMES for k in (1,28,65)]))

if ROLE=='RU':
    # Read only the exact mounted listener, route policy, and safe diagnostics env.
    for name in ['mnebydns-personal-dot-private','mnebydns-personal-dot']:
        rc,t,e=run(['docker','inspect',name])
        if rc:continue
        j=json.loads(t)[0];env=dict(x.split('=',1) for x in j['Config'].get('Env',[]) if '=' in x)
        d={'name':name,'started':j['State']['StartedAt'],'restarts':j['RestartCount'],'mounts':[{'source':m['Source'],'destination':m['Destination']} for m in j.get('Mounts',[]) if 'mnebydns' in m['Destination'] or 'dns-policy' in m['Destination']]}
        d['policy_config']={k:v for k,v in env.items() if re.search(r'(ROUTE_POLICY_(FILE|SHA256)|UPSTREAM_(HOST|PORT)|LISTEN_(HOST|PORT)|CACHE.*(MS|TTL)|TIMEOUT_MS)$',k)}
        for dst in ['/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts',env.get('MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE','')]:
            if not dst:continue
            rc,txt,e=run(['docker','exec',name,'cat',dst])
            if rc==0:OUT['sources']['docker:'+name+':'+dst]={'sha256':hashlib.sha256(txt.encode()).hexdigest(),'size':len(txt.encode()),'content':clean(txt)}
        rc,t,e=run(['docker','logs','--since','24h','--tail','10000',name],15)
        d['logs_categories']=dict(collections.Counter(category(l) for l in (t+e).splitlines() if re.search(r'(?i)error|failed|timeout|warn',l)))
        OUT.setdefault('containers',[]).append(d)

OUT['done']=True
print(json.dumps(OUT,ensure_ascii=False))
