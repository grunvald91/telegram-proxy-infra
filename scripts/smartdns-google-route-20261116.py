import pathlib,subprocess,datetime,shutil,json,time,socket,ssl,struct,os
HOSTS=['www.google.com','generativelanguage.googleapis.com','daily-cloudcode-pa.googleapis.com','play.googleapis.com','aicode.googleapis.com','oauth2.googleapis.com']
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if p.returncode:raise RuntimeError('command failed '+args[0]+': '+p.stderr[-300:])
 return p.stdout
def dns(host):
 ctx=ssl.create_default_context();q=struct.pack('!HHHHHH',491,256,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+b'\0\0\1\0\1'
 with socket.create_connection(('89.125.90.101',853),4) as raw:
  raw.settimeout(5)
  with ctx.wrap_socket(raw,server_hostname='dns.mnebyvpn.site') as s:
   s.sendall(struct.pack('!H',len(q))+q);data=b''
   while len(data)<2:data+=s.recv(2-len(data))
   n=int.from_bytes(data,'big');data=b''
   while len(data)<n:
    b=s.recv(n-len(data));assert b,'EOF';data+=b
   assert data[:2]==q[:2] and data[3]&15==0,'DNS error'
   return {'answers':int.from_bytes(data[6:8],'big'),'maps89':socket.inet_aton('89.125.90.101') in data,'maps188':socket.inet_aton('188.120.254.223') in data}

p=pathlib.Path('/opt/mnebydns-dot/Corefile');old=p.read_text()
assert '# Verified Google RU ingress 20261116' not in old
root=pathlib.Path('/var/backups/mnebydns-google-route-20261116-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S'));root.mkdir(mode=0o700,parents=True);shutil.copy2(p,root/'Corefile')
rollback=root/'rollback.sh';rollback.write_text('#!/bin/bash\nset -eu\ncat '+str(root/'Corefile')+' > '+str(p)+'\nsystemctl restart mnebydns-dot.service\n');rollback.chmod(0o700)
timer='mnebydns-google-route-revert-'+str(os.getpid());run(['systemd-run','--quiet','--unit='+timer,'--on-active=4m','bash',str(rollback)])
try:
 block='\n# Verified Google RU ingress 20261116\n'+' '.join('tls://'+h+':853' for h in HOSTS)+' {\n    bind 89.125.90.101\n    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n    template IN A {\n        answer "{{ .Name }} 20 IN A 188.120.254.223"\n    }\n    template IN AAAA { rcode NOERROR }\n    template IN HTTPS { rcode NOERROR }\n    template IN SVCB { rcode NOERROR }\n    forward . tls://9.9.9.9 { tls_servername dns.quad9.net }\n    errors\n}\n'
 p.write_text(old+block);run(['systemctl','restart','mnebydns-dot.service']);time.sleep(3)
 assert run(['systemctl','is-active','mnebydns-dot.service']).strip()=='active'
 checks={h:dns(h) for h in HOSTS}
 assert all(v['maps188'] and not v['maps89'] for v in checks.values()),'route verification failed'
 assert dns('www.youtube.com')['maps89'] and not dns('stun.l.google.com')['maps89']
 run(['systemctl','stop',timer+'.timer'])
 print(json.dumps({'ok':True,'role':'DE','backup':str(root),'route':'Google selected domains via existing RU188 ingress','dns':checks}))
except Exception as e:
 p.write_text(old);subprocess.run(['systemctl','restart','mnebydns-dot.service'],capture_output=True,timeout=30)
 print(json.dumps({'ok':False,'error':str(e),'rolled_back':True}));raise SystemExit(1)
