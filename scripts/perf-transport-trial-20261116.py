#!/usr/bin/env python3
"""Bounded parallel WG/AWG trials. Never modifies the active tg-relay config."""
import base64,concurrent.futures,datetime,fcntl,json,os,pathlib,re,signal,socket,subprocess,sys,time
ROOT=pathlib.Path('/opt/mnebyvpn/perf-trial-20261116')
BIN=pathlib.Path('/opt/mnebydns-awg-prod-20261116/bin')
N=4*1024*1024
PORT=18895
ROLE=sys.argv[2]
assert ROLE in ['DE','RU']
LOCAL='1' if ROLE=='DE' else '2';PEER='2' if ROLE=='DE' else '1'
PUBLIC='89.125.90.101' if ROLE=='DE' else '188.120.254.223'
OTHER='188.120.254.223' if ROLE=='DE' else '89.125.90.101'
STATE=ROOT/('state-'+ROLE+'.json')
TIMER='mneby-perf-trial-cleanup-'+ROLE.lower()+'-20261116'
def run(args,timeout=20,check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:raise RuntimeError(args[0]+' rc='+str(p.returncode))
    return p
def save(path,data):
    p=pathlib.Path(path);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
def config(path):
    result={'Interface':{},'Peer':{}};section=None;counts={}
    for line in pathlib.Path(path).read_text().splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if line.startswith('['):section=line.strip('[]');counts[section]=counts.get(section,0)+1;continue
        if section in result and '=' in line:
            key,value=line.split('=',1);result[section][key.strip()]=value.strip()
    assert counts=={'Interface':1,'Peer':1}
    for section,key in [('Interface','PrivateKey'),('Peer','PublicKey')]:assert len(base64.b64decode(result[section][key],validate=True))==32
    return result
def counters():
    out={}
    for name in ['snmp','netstat']:
        rows=pathlib.Path('/proc/net/'+name).read_text().splitlines()
        for a,b in zip(rows[::2],rows[1::2]):
            x,y=a.split(),b.split()
            if x and y and x[0]==y[0]:
                for key,value in zip(x[1:],y[1:]):
                    if value.isdigit() and any(t in key.lower() for t in ['error','drop','reasm','frag','timeout','retrans']):out[x[0]+key]=int(value)
    return out
def inspect_runtime():
    c=config('/etc/amnezia/amneziawg/tg-relay.conf')
    params={k:v for k,v in c['Interface'].items() if k in ['MTU','ListenPort','Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','ContentPaddingAddition','RandomTrailers']}
    sockets=run(['ss','-ulnpem'],check=False).stdout.splitlines();selected=[]
    for i,line in enumerate(sockets):
        if 'amneziawg-go' in line:
            text=line+' '+(sockets[i+1] if i+1<len(sockets) else '')
            selected.extend(re.findall(r'skmem:\([^)]*\)',text))
    return {'params':params,'udp_socket_memory':selected,'sysctl':{k:pathlib.Path('/proc/sys/net/core/'+k).read_text().strip() for k in ['rmem_max','rmem_default','wmem_max','wmem_default']},'counters':counters()}
def stage():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if STATE.exists() and not json.loads(STATE.read_text()).get('cleaned'):raise RuntimeError('Uncleaned trial state already exists')
    for name in ['mn-perf-wg','mn-perf-awg']:
        if run(['ip','link','show',name],check=False).returncode==0:raise RuntimeError('Trial interface already exists')
    if STATE.exists():
        for name in ['mn-perf-wg.conf','mn-perf-awg.conf']:(ROOT/name).unlink(missing_ok=True)
    state={'role':ROLE,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'interfaces':[],'rules':[],'available':{'current':'10.66.77.'+LOCAL},'before':inspect_runtime()};save(STATE,state)
    deadline=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=4)).strftime('%Y-%m-%d %H:%M:%S UTC')
    pathlib.Path('/etc/systemd/system/'+TIMER+'.service').write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(ROOT/'perf.py')+' cleanup '+ROLE+'\n')
    pathlib.Path('/etc/systemd/system/'+TIMER+'.timer').write_text('[Timer]\nOnCalendar='+deadline+'\nPersistent=true\nUnit='+TIMER+'.service\n[Install]\nWantedBy=timers.target\n')
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',TIMER+'.timer'])
    for mode,subnet,port in [('wg','88',46673 if ROLE=='DE' else 46674),('awg','89',46683 if ROLE=='DE' else 46684)]:
        name='mn-perf-'+mode;cfg=ROOT/(name+'.conf')
        try:
            if run(['ip','route','show','10.66.'+subnet+'.0/30'],check=False).stdout.strip():raise RuntimeError('Trial subnet already routed')
            c=config('/etc/wireguard/tg-relay.conf' if mode=='wg' else '/etc/amnezia/amneziawg/tg-relay.conf')
            lines=['[Interface]','PrivateKey = '+c['Interface']['PrivateKey'],'ListenPort = '+str(port),'Address = 10.66.'+subnet+'.'+LOCAL+'/30','MTU = 1280','Table = off']
            if mode=='awg':
                allow=['Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','HeaderProtectionKey','ContentPaddingAddition','RandomTrailers']
                lines.extend(k+' = '+c['Interface'][k] for k in allow if k in c['Interface'])
            lines+=['[Peer]','PublicKey = '+c['Peer']['PublicKey'],'AllowedIPs = 10.66.'+subnet+'.'+PEER+'/32','Endpoint = '+OTHER+':'+str(port+1 if ROLE=='DE' else port-1),'PersistentKeepalive = 5']
            if 'PresharedKey' in c['Peer']:lines.append('PresharedKey = '+c['Peer']['PresharedKey'])
            fd=os.open(cfg,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:f.write('\n'.join(lines)+'\n')
            rule=['-s',OTHER+'/32','-p','udp','--dport',str(port),'-m','comment','--comment','mneby-perf-'+mode+'-20261116','-j','ACCEPT']
            state['rules'].append(rule);save(STATE,state);run(['iptables','-w','5','-I','INPUT','1']+rule)
            state['interfaces'].append({'name':name,'mode':mode,'config':str(cfg)});save(STATE,state)
            quick='/usr/bin/wg-quick' if mode=='wg' else str(BIN/'awg-quick')
            env=dict(os.environ,PATH=str(BIN)+':'+os.environ['PATH'],WG_QUICK_USERSPACE_IMPLEMENTATION=str(BIN/'amneziawg-go')) if mode=='awg' else dict(os.environ)
            p=subprocess.run([quick,'up',str(cfg)],capture_output=True,text=True,timeout=30,env=env)
            if p.returncode:raise RuntimeError('Trial quick up failed')
            state['available'][mode]='10.66.'+subnet+'.'+LOCAL
        except Exception as e:state.setdefault('stage_errors',{})[mode]=str(e)
        save(STATE,state)
    for mode,local in state['available'].items():
        rule=['-i','tg-relay' if mode=='current' else 'mn-perf-'+mode,'-s',local.rsplit('.',1)[0]+'.'+PEER+'/32','-d',local+'/32','-p','tcp','--dport',str(PORT),'-m','comment','--comment','mneby-perf-tcp-'+mode+'-20261116','-j','ACCEPT']
        state['rules'].append(rule);save(STATE,state);run(['iptables','-w','5','-I','INPUT','1']+rule)
    with open(ROOT/('serve-'+ROLE+'.log'),'w') as out:
        p=subprocess.Popen([sys.executable,str(ROOT/'perf.py'),'serve',ROLE],stdout=out,stderr=out,start_new_session=True)
    state['server_pid']=p.pid;save(STATE,state)
    print(json.dumps({'role':ROLE,'available':state['available'],'stage_errors':state.get('stage_errors',{}),'runtime':state['before']}))
def ping(item):
    mode,address=item
    target=address.rsplit('.',1)[0]+'.'+PEER
    cmd=['ping','-n','-q','-M','do','-s','1200','-c','200','-i','0.05','-W','1',target]
    p=run(cmd,22,False);text=p.stdout
    counts=re.search(r'(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss',text)
    rtt=re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/',text)
    return mode,{'sent':int(counts[1]) if counts else None,'received':int(counts[2]) if counts else None,'loss_pct':float(counts[3]) if counts else None,'rtt_avg_ms':float(rtt[2]) if rtt else None,'rc':p.returncode}
def measure():
    state=json.loads(STATE.read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:result=dict(pool.map(ping,state['available'].items()))
    save(ROOT/('ping-'+ROLE+'.json'),result);print(json.dumps({'role':ROLE,'ping':result,'runtime_after':inspect_runtime()}))
def serve_one(item):
    mode,local=item;result={'mode':mode}
    try:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((local,PORT));s.listen(1);s.settimeout(100)
            with s.accept()[0] as c:
                c.settimeout(20)
                if c.getpeername()[0]!=local.rsplit('.',1)[0]+'.'+PEER or c.recv(1)!=b'R':raise RuntimeError('Wrong benchmark peer')
                c.sendall(b'x'*N)
                if c.recv(1)!=b'U':raise RuntimeError('Missing upload marker')
                count=0;start=time.monotonic()
                while count<N:
                    b=c.recv(min(65536,N-count))
                    if not b:break
                    count+=len(b)
                elapsed=time.monotonic()-start
                result.update(ru_to_de_bytes=count,ru_to_de_mbps=round(count*8/elapsed/1e6,2),complete=count==N)
    except Exception as e:result['error']=type(e).__name__
    save(ROOT/('tcp-server-'+mode+'-'+ROLE+'.json'),result)
def serve():
    state=json.loads(STATE.read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(serve_one,state['available'].items()))
def bench():
    assert ROLE=='RU';state=json.loads(STATE.read_text());result=[]
    for mode,address in state['available'].items():
        row={'mode':mode}
        try:
            with socket.create_connection((address.rsplit('.',1)[0]+'.1',PORT),timeout=4) as s:
                s.settimeout(20);s.sendall(b'R');count=0;start=time.monotonic()
                while count<N:
                    b=s.recv(min(65536,N-count))
                    if not b:break
                    count+=len(b)
                elapsed=time.monotonic()-start
                row.update(de_to_ru_bytes=count,de_to_ru_mbps=round(count*8/elapsed/1e6,2),complete=count==N)
                s.sendall(b'U'+b'x'*N)
        except Exception as e:row['error']=type(e).__name__
        result.append(row)
    print(json.dumps(result))
def collect():
    out={'role':ROLE,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runtime':inspect_runtime()}
    for p in ROOT.glob('*-'+ROLE+'.json'):
        if not p.name.startswith('state'):out[p.stem]=json.loads(p.read_text())
    print(json.dumps(out))
def cleanup():
    if not STATE.exists():return
    state=json.loads(STATE.read_text());pid=state.get('server_pid')
    if pid:
        p=pathlib.Path('/proc')/str(pid)/'cmdline'
        if p.exists() and str(ROOT/'perf.py').encode() in p.read_bytes():
            try:os.kill(pid,signal.SIGTERM)
            except ProcessLookupError:pass
    for item in reversed(state['interfaces']):
        quick='/usr/bin/wg-quick' if item['mode']=='wg' else str(BIN/'awg-quick')
        env=dict(os.environ,PATH=str(BIN)+':'+os.environ['PATH'],WG_QUICK_USERSPACE_IMPLEMENTATION=str(BIN/'amneziawg-go'))
        subprocess.run([quick,'down',item['config']],capture_output=True,text=True,timeout=30,env=env)
        if run(['ip','link','show',item['name']],check=False).returncode==0:run(['ip','link','delete',item['name']],check=False)
        pathlib.Path(item['config']).unlink(missing_ok=True)
    for rule in reversed(state['rules']):
        if run(['iptables','-w','5','-C','INPUT']+rule,check=False).returncode==0:run(['iptables','-w','5','-D','INPUT']+rule)
    state['cleaned']=True;save(STATE,state)
    run(['systemctl','disable','--now',TIMER+'.timer'],check=False)
    print('PARALLEL_TRIAL_CLEANED='+ROLE)

if __name__=='__main__':
    assert os.geteuid()==0
    {'stage':stage,'measure':measure,'serve':serve,'bench':bench,'collect':collect,'cleanup':cleanup}[sys.argv[1]]()
