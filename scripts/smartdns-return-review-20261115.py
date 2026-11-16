import socket,struct,subprocess,pathlib,json,collections,datetime,time,re,concurrent.futures
START=1794805437
EXPECTED={'6686c221bf2d6613e8d29b8ec1fe04c02c7190a317ef52334064f6cabbdd918a': 'youtube_0', 'ac7af6b190d852cd4223a13b3552912b2673d1d8d9883edf95ae741e8edb421e': 'youtube_1', '8ab73cad277cdf2ac99cba58c5354085f7ca9eb259b4f8771071cc3b93fa45c7': 'youtube_2', '08e882e1bdeb293b95cee96a2161d15aaa2bf09e56abafa0d7a8ec1f47bde405': 'googlevideo_0', 'cc838ec97735ab14701b6f70f0ba5988aeeffb928073ed5113c5da55c5c39798': 'googlevideo_1', '72cef6d84856344fb167660ab414cbb798f1ca232dad635b753cbcb02c225a14': 'googlevideo_2', '4c3a04ce05ee37dc26759a2cc010ed786955702c3bde4f5a665491ccce53f1ce': 'google_0', '039e271ed92a8cc16a693f6ed81df1a197c0f360eaf512f58b22edff9de59d34': 'google_1', 'f4d2adbcde306cfc9d78025b93648a8556ff8982e01b454ed1a5261e66130176': 'google_2'}
OUT={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def run(a):
    try:return subprocess.run(a,capture_output=True,text=True,timeout=12).stdout
    except Exception as e:return type(e).__name__
def redact(s):
    s=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',lambda m:m[0] if m[0] in ('89.125.90.101','188.120.254.223','10.66.77.1','10.66.77.2','127.0.0.1','0.0.0.0') else '<ip>',s)
    s=re.sub(r'\b[a-z0-9]{12}\.dns\.mnebyvpn\.site','<personal>.dns.mnebyvpn.site',s)
    return s
def capture():
    d={'start':datetime.datetime.now(datetime.timezone.utc).isoformat(),'flows':{}}
    active={};events=collections.defaultdict(list)
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('eth0',0));s.settimeout(.25)
    while time.time()<START+23:
        try:b,addr=s.recvfrom(20000)
        except socket.timeout:continue
        if len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
        off=14+(b[14]&15)*4
        if len(b)<off+20:continue
        sp,dp,seq,ack=struct.unpack('!HHII',b[off:off+12]);flags=b[off+13];hdr=(b[off+12]>>4)*4
        src,dst=b[26:30],b[30:34];plen=int.from_bytes(b[16:18],'big')-(off-14)-hdr;p=b[off+hdr:]
        if dp==443:
            key=(src,sp)
            if len(p)>=43 and p[0]==22 and p[5]==1 and p[11:43].hex() in EXPECTED:
                label=EXPECTED[p[11:43].hex()];active[key]=label
                d['flows'].setdefault(label,{'hello_received':True,'events':[]})
            if key not in active:continue
            label=active[key];direction='client_to_server'
        elif sp==443 and (dst,dp) in active:
            label=active[(dst,dp)];direction='server_to_client'
        else:continue
        if len(d['flows'][label]['events'])<100:
            d['flows'][label]['events'].append({'since_start_ms':round((time.time()-START)*1000),'direction':direction,'flags':flags,'payload_bytes':max(0,plen),'tls_record_type':p[0] if p and p[0] in (20,21,22,23) else None,'seq':seq,'ack':ack,'ttl':b[22]})
    s.close();d['end']=datetime.datetime.now(datetime.timezone.utc).isoformat();return d
pool=concurrent.futures.ThreadPoolExecutor(max_workers=1);future=pool.submit(capture)
OUT['iptables']=redact(run(['iptables-save','-c']))
OUT['nft']=redact(run(['nft','list','ruleset']))
OUT['nfqueue_before']=run(['cat','/proc/net/netfilter/nfnetlink_queue'])
OUT['nfqws_units']={u:redact(run(['systemctl','cat',u])) for u in ['telegram-foreign-nfqws.service','telegram-foreign-mss-rules.service','telegram-rf-media-rules.service']}
OUT['nfqws_sources']={}
for p in ['/etc/zapret2/telegram-nfqws.conf','/usr/local/sbin/telegram-foreign-mss-rules.sh','/usr/local/sbin/telegram-rf-media-rules.sh']:
    x=pathlib.Path(p)
    if x.is_file():OUT['nfqws_sources'][p]=redact(x.read_text(errors='replace'))
OUT['trace']=future.result();pool.shutdown()
OUT['nfqueue_after']=run(['cat','/proc/net/netfilter/nfnetlink_queue'])
OUT['done']=True
print(json.dumps(OUT))
