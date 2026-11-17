#!/usr/bin/env python3
"""Inspect DE89 services and revalidate the observed phone's actual personal DoT.

Only an unambiguous existing phone DoT socket may be reconnected. Credentials,
addresses, packet payload and the personal hostname are never printed.
"""
import hashlib, importlib.util, ipaddress, json, os, pathlib, re, signal, socket, ssl, struct, subprocess, time
ROOT=pathlib.Path(__file__).resolve().parent
def run(a,timeout=10):
    try:
        p=subprocess.run(a,capture_output=True,text=True,timeout=timeout)
        return p.returncode,p.stdout
    except (OSError,subprocess.TimeoutExpired) as e:return -1,type(e).__name__
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
for unit in ['nginx','mnebydns-googlepilot','mnebydns-dot','mnebydns-personal-sni-stream','mnebydns-personal-sni-redirect','telegram-foreign-nfqws']:
    emit('SERVICE',{'unit':unit,'state':run(['systemctl','is-active',unit])[1].strip()})
rc,raw=run(['nft','-j','list','ruleset'])
if rc or any(tag in raw for tag in ['mnebydns_youtube_window4_test','mnebydns_youtube_synsplit_test']):raise RuntimeError('TCP_EXPERIMENT_NOT_CLEAN')
emit('TEMPORARY_TCP_RULES_ABSENT',True)
for path in ['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/opt/mnebydns-dot/Corefile']:
    if pathlib.Path(path).is_file():emit('CONFIG_HASH',{'path':path,'sha256':hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()})
config=pathlib.Path('/etc/mnebydns/personal-sni/nginx.conf')
front_port=853
if config.exists():
    content=config.read_text()
    ports={int(v.rsplit(':',1)[-1]) for v in re.findall(r'^\s*listen\s+([^;\s]+)',content,re.M) if v.rsplit(':',1)[-1].isdigit()}
    if len(ports)==1:front_port=next(iter(ports))
    targets=re.findall(r'10\.66\.77\.2:(\d+)',content)
    emit('PERSONAL_SNI_PATH',{'frontend_port':front_port,'backend_ports':targets,'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest()})
for port in sorted({853,front_port}):
    rc,out=run(['ss','-Hlnpt','(','sport','=',':'+str(port),')'])
    emit('LISTENER',{'port':port,'present':bool(out.strip()),'exit':rc})
if config.exists():
    for backend_port in sorted({int(x) for x in targets}):
        try:
            with socket.create_connection(('10.66.77.2',backend_port),timeout=5) as raw:
                raw.settimeout(5)
                with ssl.create_default_context().wrap_socket(raw,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
                    emit('EXISTING_PERSONAL_DNS_BACKEND_TLS',{'port':backend_port,'verified':bool(tls.getpeercert()),'version':tls.version()})
        except Exception as e:emit('EXISTING_PERSONAL_DNS_BACKEND_TLS',{'port':backend_port,'error':type(e).__name__})
source=pathlib.Path('/run/mnebydns-w4-44047955995-1/PHONE_SOURCE.json')
if not source.exists():emit('PERSONAL_DOT_RECHECK','NO_PRIOR_OBSERVED_SOURCE');raise SystemExit(0)
record=json.loads(source.read_text());addr=record['address']
if not ipaddress.ip_address(addr).is_global or time.time()-record['observed_at']>2400:emit('PERSONAL_DOT_RECHECK','STALE_SOURCE');raise SystemExit(0)
expr=['(','sport','=',':'+str(front_port),'and','dst',addr,')']
rc,out=run(['ss','-Hnt','state','established',*expr])
rows=out.strip().splitlines() if out.strip() else []
emit('OBSERVED_SOURCE_ACTIVE_DOT_SOCKETS',len(rows))
if rc or len(rows)!=1:emit('PERSONAL_DOT_RECHECK','NO_UNAMBIGUOUS_ACTIVE_SOCKET');raise SystemExit(0)
peer=rows[0].split()[-1];port=peer.rsplit(':',1)[-1]
if not port.isdigit():raise RuntimeError('BAD_SOCKET_METADATA')
spec=importlib.util.spec_from_file_location('obs',ROOT/'observer.py');obs=importlib.util.module_from_spec(spec);spec.loader.exec_module(obs)
capture=subprocess.Popen(['timeout','20','tcpdump','-i','eth0','-n','-U','-B','16384','-s','8192','-w','-','ip and tcp and src host '+addr+' and dst port 853'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
host=None;chunks={}
try:
    endian,link=obs.read_header(capture.stdout)
    rc,_=run(['ss','-K','state','established','(','sport','=',':'+str(front_port),'and','dst',addr,'and','dport','=',':'+port,')'])
    emit('SINGLE_OBSERVED_DOT_SOCKET_RECONNECTED',rc==0)
    while True:
        h=obs.read_exact(capture.stdout,16)
        if h is None:break
        _,_,cap,_=struct.unpack(endian+'IIII',h)
        if cap>8192:raise RuntimeError('BAD_PCAP_PREFIX')
        frame=obs.read_exact(capture.stdout,cap)
        if frame is None:raise RuntimeError('SHORT_PCAP')
        pkt=obs.decode(frame,link)
        if pkt and pkt[-1]:
            obs.remember(chunks,pkt[4],pkt[-1]);candidate=obs.tls_sni(obs.join_segments(chunks))
            if candidate and re.fullmatch(r'[a-z0-9_-]+\.dns\.mnebyvpn\.site',candidate):host=candidate;break
finally:
    if capture.poll() is None:capture.send_signal(signal.SIGINT)
    _,stats=capture.communicate(timeout=10)
emit('ACTUAL_PERSONAL_HOST_OBSERVED',bool(host))
if not host:emit('PERSONAL_DOT_RECHECK','RECONNECT_SNI_NOT_OBSERVED');raise SystemExit(0)
(ROOT/'PERSONAL_HOST').write_text(host);os.chmod(ROOT/'PERSONAL_HOST',0o600)
for af,label in [(socket.AF_INET,'A'),(socket.AF_INET6,'AAAA')]:
    try:
        addrs={x[4][0] for x in socket.getaddrinfo(host,853,af,socket.SOCK_STREAM)}
        emit('ACTUAL_HOST_BOOTSTRAP',{'type':label,'count':len(addrs),'DE89_included':'89.125.90.101' in addrs})
    except socket.gaierror as e:emit('ACTUAL_HOST_BOOTSTRAP',{'type':label,'error_code':e.errno})
def strip(buf,p):
    for _ in range(128):
        n=buf[p];p+=1
        if n&192==192:return p+1
        if not n:return p
        p+=n
    raise ValueError('DNS_NAME')
def query(domain,typ):
    ident=os.urandom(2);q=ident+b'\x01\x00\x00\x01'+b'\x00'*6
    q+=b''.join(bytes([len(x)])+x.encode() for x in domain.split('.'))+b'\x00'+struct.pack('!HH',typ,1)
    with socket.create_connection(('89.125.90.101',853),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as conn:
            conn.settimeout(5);conn.sendall(struct.pack('!H',len(q))+q)
            prefix=bytearray()
            while len(prefix)<2:
                part=conn.recv(2-len(prefix))
                if not part:raise EOFError()
                prefix.extend(part)
            size=struct.unpack('!H',prefix)[0]
            if size<12 or size>16384:raise ValueError('DNS_SIZE')
            body=bytearray()
            while len(body)<size:
                part=conn.recv(size-len(body))
                if not part:raise EOFError()
                body.extend(part)
    b=bytes(body)
    if b[:2]!=ident:raise ValueError('DNS_ID')
    code=int.from_bytes(b[2:4],'big')&15;p=strip(b,12)+4;addresses=[]
    for _ in range(int.from_bytes(b[6:8],'big')):
        p=strip(b,p);t,cl,ttl,n=struct.unpack('!HHIH',b[p:p+10]);p+=10
        if t==1 and n==4:addresses.append(socket.inet_ntoa(b[p:p+n]))
        p+=n
    return {'rcode':code,'answer_count':int.from_bytes(b[6:8],'big'),'DE89_included':'89.125.90.101' in addresses,'RU188_included':'188.120.254.223' in addresses,'certificate_verified':True}
for domain,typ in [('example.org',1),('youtubei.googleapis.com',1),('i.ytimg.com',1),('yt3.ggpht.com',1),('rr1---sn-gxuo03g-ig3s.googlevideo.com',1),('rr1---sn-gxuo03g-ig3s.googlevideo.com',28),('rr1---sn-gxuo03g-ig3s.googlevideo.com',65)]:
    try:emit('ACTUAL_PERSONAL_DOT_ANSWER',{'domain':domain,'type':typ,**query(domain,typ)})
    except Exception as e:emit('ACTUAL_PERSONAL_DOT_ERROR',{'domain':domain,'type':typ,'error':type(e).__name__})
emit('NO_DNS_OR_NGINX_CONFIGURATION_EDITS',True)
