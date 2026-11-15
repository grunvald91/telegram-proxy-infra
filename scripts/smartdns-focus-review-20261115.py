import collections,concurrent.futures,datetime,hashlib,json,pathlib,re,socket,ssl,struct,subprocess,time,sys
ROLE=sys.argv[1]
OUT={'role':ROLE,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
EXPECTED={'9108213aa020b901bb853c5a1d05e0ba015427774dc9133e6eace8180842f625': 'youtube_0', '19e05c4b67c8e2053d5f29e7fe553ea56542532a5ffa1ddadf91aea19425ed7d': 'youtube_1', 'e2cf4a259e7901cec0a2cc27ac96e861b68036a105e3e15c9aae84af082ac0bd': 'youtube_2', '6021a9a198ca464eadcb807e63e6a018cf45d414fb49ea825efd39ff0636c684': 'googlevideo_0', 'ed9b0c9aac496b4dbee60968ebd9232bafa850955fa4b49d5922ccf8e43d2e9f': 'googlevideo_1', '330fd660b58483194ba04ceb80333c2673fa9178df8816658c991d27e709cf61': 'googlevideo_2', 'cacd6b8fb20db0b610aafd36a7e4618a988fbc6982b60cce9b386554c032faf6': 'google_0', '3e158ef768b32621dd4fccde9ca298076e6c232803c98844c7622d5647201eec': 'google_1', '0312883a5da803b5e7d980aac357d5d9d6eccbf0f08b3404ed5dae366986c7d9': 'google_2'}
START=1794773236

def cmd(a,t=15):
    try:
        p=subprocess.run(a,capture_output=True,text=True,timeout=t);return p.stdout+p.stderr
    except Exception as e:return type(e).__name__
def safe(msg):
    # Retain only error reason, never request details or customer addresses.
    msg=re.split(r', (?:client|server|upstream|request|host):',msg)[0]
    msg=re.sub(r'https?://\S+','<url>',msg)
    msg=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<ip>',msg)
    msg=re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b','<uuid>',msg)
    msg=re.sub(r'\b[0-9a-zA-Z_-]{32,}\b','<id>',msg)
    msg=re.sub(r'\b[0-9a-z]{12}\.dns\.mnebyvpn\.site','<personal>.dns.mnebyvpn.site',msg)
    return msg[:330]
def errors():
    out={}
    for u in ['nginx','xray','mnebydns-googlepilot','mnebydns-personal-sni-stream','mnebydns-personal-sni-watch']:
        s=cmd(['journalctl','-u',u,'--since','24 hours ago','-n','5000','-o','cat','--no-pager'])
        c=collections.Counter()
        for l in s.splitlines():
            if re.search(r'(?i)warn|error|failed|timeout|timed out|refused',l):c[safe(l)]+=1
        out[u]=c.most_common(15)
    s=cmd(['journalctl','-k','--since','24 hours ago','-p','warning','-n','10000','-o','cat','--no-pager'])
    c=collections.Counter()
    for l in s.splitlines():
        # Firewall packet logs contain personal IPs; classify prefix and ports only.
        if 'SRC=' in l:
            p=re.search(r'(?:DPT|DSTPORT)=(\d+)',l);proto=re.search(r'PROTO=(\w+)',l)
            c['packet_log '+str(proto[1] if proto else '?')+' dport='+str(p[1] if p else '?')]+=1
        else:c[safe(l)]+=1
    out['kernel']=c.most_common(20)
    return out
def tls(v):
    ip,port,h=v;d={'ip':ip,'port':port,'host':h};t=time.monotonic()
    try:
        with socket.create_connection((ip,port),timeout=4) as s:
            s.settimeout(5)
            with ssl.create_default_context().wrap_socket(s,server_hostname=h) as c:
                d['tls']='PASS';c.sendall(('GET / HTTP/1.1\r\nHost: '+h+'\r\nConnection: close\r\n\r\n').encode());d['http']=c.recv(300).split(b'\r\n')[0].decode(errors='replace')
    except Exception as e:d['error']=type(e).__name__
    d['ms']=round((time.monotonic()-t)*1000);return d
def capture():
    result={'expected_labels':list(EXPECTED.values()),'seen':{},'start':None,'end':None}
    try:
        s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('eth0',0));s.settimeout(.3)
        result['start']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        while time.time()<START+23:
            try:b,a=s.recvfrom(10000)
            except socket.timeout:continue
            # Incoming IPv4/TCP/443 only. Discard packet bytes immediately.
            if a[2]==4 or len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
            off=14+(b[14]&15)*4
            if len(b)<off+20 or int.from_bytes(b[off+2:off+4],'big')!=443:continue
            off+=(b[off+12]>>4)*4;p=b[off:]
            if len(p)<43 or p[0]!=22 or p[5]!=1:continue
            marker=p[11:43].hex()
            if marker in EXPECTED:
                label=EXPECTED[marker];result['seen'][label]=result['seen'].get(label,0)+1
        s.close();result['end']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    except Exception as e:result['error']=type(e).__name__
    return result

pool=concurrent.futures.ThreadPoolExecutor(max_workers=4)
cap=pool.submit(capture) if ROLE=='DE' else None
OUT['errors']=errors()
OUT['non443_listeners']=[re.sub(r'users:.*','',l).strip() for l in cmd(['ss','-H','-lntu']).splitlines() if re.search(r':(?:80|123|5222|5228|5229|5230|19302)\s',l)]
if ROLE=='DE':
    jobs=[(ip,port,h) for ip,port in [('89.125.90.101',443),('127.0.0.1',15449)] for h in ['www.youtube.com','rr1---sn-gxuo03g-ig3s.googlevideo.com','www.google.com','speech.googleapis.com','aicode.googleapis.com']]
    OUT['server_tls']=list(pool.map(tls,jobs))
else:
    name='mnebydns-personal-dot-private';sources={}
    for p in ['/srv/mnebyvpn/packages/dns-policy/src/personal-dot-gateway-core.ts','/run/mnebydns-personal/personal-dot-production.ts']:
        t=cmd(['docker','exec',name,'cat',p]);sources[p]={'sha256':hashlib.sha256(t.encode()).hexdigest(),'content':t}
    OUT['sources']=sources
if cap:OUT['controlled_clienthello_capture']=cap.result()
pool.shutdown()
OUT['done']=True
print(json.dumps(OUT,ensure_ascii=False))
