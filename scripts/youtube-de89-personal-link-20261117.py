#!/usr/bin/env python3
"""Test the supplied personal link without publishing its access identifier."""
import base64,hashlib,hmac,json,os,pathlib,re,socket,ssl,struct,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parent
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def run(a,data=None):
    p=subprocess.run(a,input=data,capture_output=True,timeout=10)
    if p.returncode:raise RuntimeError('CRYPTO_COMMAND_FAILED')
    return p.stdout
def string(b,p):
    n=int.from_bytes(b[p:p+4],'big');p+=4
    if n>len(b)-p:raise RuntimeError('KEY_FORMAT')
    return b[p:p+n],p+n
def decrypt():
    e=json.loads((ROOT/'input.enc.json').read_text())
    if e['version']!=1:raise RuntimeError('INPUT_VERSION')
    raw=pathlib.Path('/etc/ssh/ssh_host_ed25519_key').read_text()
    b=base64.b64decode(''.join(x for x in raw.splitlines() if not x.startswith('---')))
    magic=b'openssh-key-v1\x00'
    if not b.startswith(magic):raise RuntimeError('KEY_FORMAT')
    p=len(magic);cipher,p=string(b,p);kdf,p=string(b,p);options,p=string(b,p)
    if cipher!=b'none' or kdf!=b'none':raise RuntimeError('HOST_KEY_ENCRYPTED')
    n=int.from_bytes(b[p:p+4],'big');p+=4
    if n!=1:raise RuntimeError('HOST_KEY_COUNT')
    public,p=string(b,p);private,p=string(b,p)
    if private[:4]!=private[4:8]:raise RuntimeError('KEY_CHECK')
    typ,p=string(private,8);pub,p=string(private,p);secret,p=string(private,p)
    if typ!=b'ssh-ed25519' or len(secret)!=64 or secret[32:]!=pub:raise RuntimeError('KEY_TYPE')
    scalar=bytearray(hashlib.sha512(secret[:32]).digest()[:32]);scalar[0]&=248;scalar[31]&=127;scalar[31]|=64
    ephemeral,iv,ciphertext,tag=[base64.b64decode(e[x]) for x in ['ephemeral','iv','ciphertext','tag']]
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        key=pathlib.Path(folder)/'key.der';peer=pathlib.Path(folder)/'peer.der'
        key.write_bytes(bytes.fromhex('302e020100300506032b656e04220420')+scalar);key.chmod(0o600)
        peer.write_bytes(bytes.fromhex('302a300506032b656e032100')+ephemeral)
        shared=run(['openssl','pkeyutl','-derive','-inkey',str(key),'-keyform','DER','-peerkey',str(peer),'-peerform','DER'])
    enc=hashlib.sha256(b'mnebydns-input-encryption-v1'+shared).digest();auth=hashlib.sha256(b'mnebydns-input-authentication-v1'+shared).digest()
    if not hmac.compare_digest(tag,hmac.new(auth,ephemeral+iv+ciphertext,hashlib.sha256).digest()):raise RuntimeError('INPUT_AUTHENTICATION_FAILED')
    value=run(['openssl','enc','-d','-aes-256-ctr','-K',enc.hex(),'-iv',iv.hex()],ciphertext).decode()
    if not re.fullmatch(r'[a-z0-9_-]+\.dns\.mnebyvpn\.site',value):raise RuntimeError('INVALID_PERSONAL_HOST')
    return value
host=decrypt();emit('PERSONAL_INPUT_DECRYPTED',True);emit('PERSONAL_TEST_PATH','PUBLIC_89_853_VIA_EXTERNAL_REVERSE_FORWARD')
for af,name in [(socket.AF_INET,'A'),(socket.AF_INET6,'AAAA')]:
    try:
        addresses={x[4][0] for x in socket.getaddrinfo(host,853,af,socket.SOCK_STREAM)}
        emit('ACTUAL_LINK_BOOTSTRAP',{'type':name,'addresses':sorted(addresses),'DE89_included':'89.125.90.101' in addresses})
    except socket.gaierror as e:emit('ACTUAL_LINK_BOOTSTRAP',{'type':name,'error_code':e.errno})
def exact(conn,n):
    b=bytearray()
    while len(b)<n:
        part=conn.recv(n-len(b))
        if not part:raise EOFError()
        b.extend(part)
    return bytes(b)
def skip(b,p):
    for _ in range(128):
        n=b[p];p+=1
        if n&192==192:return p+1
        if n==0:return p
        p+=n
    raise ValueError('DNS_NAME')
def packet(domain,typ):
    ident=os.urandom(2)
    q=ident+b'\x01\x00\x00\x01'+b'\x00'*6
    q+=b''.join(bytes([len(x)])+x.encode() for x in domain.split('.'))+b'\x00'+struct.pack('!HH',typ,1)
    return ident,struct.pack('!H',len(q))+q
def response(conn):
    n=struct.unpack('!H',exact(conn,2))[0]
    if not 12<=n<=16384:raise ValueError('DNS_SIZE')
    b=exact(conn,n);p=skip(b,12)+4;addresses=[]
    for _ in range(int.from_bytes(b[6:8],'big')):
        p=skip(b,p);t,cl,ttl,size=struct.unpack('!HHIH',b[p:p+10]);p+=10
        if t==1 and size==4:addresses.append(socket.inet_ntoa(b[p:p+size]))
        if t==28 and size==16:addresses.append(socket.inet_ntop(socket.AF_INET6,b[p:p+size]))
        p+=size
    return b[:2],{'rcode':int.from_bytes(b[2:4],'big')&15,'answer_count':int.from_bytes(b[6:8],'big'),'addresses':addresses,'DE89_included':'89.125.90.101' in addresses}
def connect():
    raw=socket.create_connection(('127.0.0.1',int(os.environ['MNEBY_PERSONAL_TEST_PORT'])),timeout=7);raw.settimeout(7)
    try:return ssl.create_default_context().wrap_socket(raw,server_hostname=host)
    except Exception:raw.close();raise
domains=['example.org','connectivitycheck.gstatic.com','www.youtube.com','youtubei.googleapis.com','i.ytimg.com','s.ytimg.com','yt3.ggpht.com','rr1---sn-gxuo03g-ig3s.googlevideo.com','redirector.googlevideo.com']
try:
    with connect() as conn:
        emit('ACTUAL_LINK_TLS',{'verified':conn.getpeercert() is not None,'version':conn.version()})
        for domain in domains:
            for typ in ([1] if domain=='example.org' else [1,28,65]):
                ident,q=packet(domain,typ);start=time.monotonic();conn.sendall(q);rid,result=response(conn)
                if rid!=ident:raise ValueError('DNS_ID')
                emit('ACTUAL_LINK_DNS',{'domain':domain,'type':typ,'ms':round((time.monotonic()-start)*1000),**result})
    tests=[(domain,1) for domain in ['youtubei.googleapis.com','i.ytimg.com','yt3.ggpht.com','rr1---sn-gxuo03g-ig3s.googlevideo.com']]
    with connect() as conn:
        pending={};wire=[]
        for domain,typ in tests:
            ident,q=packet(domain,typ);pending[ident]=(domain,typ);wire.append(q)
        conn.sendall(b''.join(wire))
        for _ in tests:
            ident,result=response(conn)
            if ident not in pending:raise ValueError('PIPELINED_DNS_ID')
            domain,typ=pending.pop(ident);emit('ACTUAL_LINK_PIPELINED_DNS',{'domain':domain,'type':typ,**result})
    emit('ACTUAL_LINK_TRANSPORT_TEST_COMPLETED',True)
except Exception as e:
    emit('ACTUAL_LINK_FAILURE',{'error':type(e).__name__});raise SystemExit(2)
emit('NO_CONFIGURATION_CHANGES',True)
