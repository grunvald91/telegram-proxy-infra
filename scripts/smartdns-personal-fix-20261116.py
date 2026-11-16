import pathlib,subprocess,json,datetime,shutil,time,os
C='mnebydns-personal-dot-private'
ROOT=pathlib.Path('/var/backups/mnebydns-personal-fix-20261116-'+datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S'));ROOT.mkdir(parents=True,mode=0o700)
def run(a):
 p=subprocess.run(a,capture_output=True,text=True,timeout=45)
 if p.returncode:raise RuntimeError('command failed '+a[0]+': '+p.stderr[-300:])
 return p.stdout
info=json.loads(run(['docker','inspect',C]))[0]
mounts=info['Mounts'];listener=next(pathlib.Path(m['Source']) for m in mounts if m['Destination'].endswith('/src/personal-dot-listener.ts'))
base=next(pathlib.Path(m['Source']) for m in mounts if m['Destination']=='/run/mnebydns-personal')
production=base/'personal-dot-production.ts'
changes={};applied=False
try:
 s=listener.read_text();assert '      }catch{stop();}' in s and 'if(pending.length>=MAX_QUEUE){stop();return;}' in s,'listener drift'
 s=s.replace('      }catch{stop();}',"      }catch(err){\n        console.warn('personal_dot_request_failed',err instanceof Error?err.name:'Error');\n        stop();\n      }")
 s=s.replace('if(pending.length>=MAX_QUEUE){stop();return;}',"if(pending.length>=MAX_QUEUE){console.warn('personal_dot_queue_overflow');stop();return;}")
 changes[listener]=(listener.read_text(),s)
 old=production.read_text();s=old
 assert 'queryTimeoutMs:8500' in s and 'mapped,query,7000' in s and 'direct,query,7000' in s,'production drift'
 s=s.replace('queryTimeoutMs:8500','queryTimeoutMs:10000').replace('mapped,query,7000','mapped,query,4000').replace('direct,query,7000','direct,query,2500')
 anchor='  let listening=false;'
 helper='''  // Cache bounded end-to-end upstream probes; readiness must include DNS.
  let dnsHealthyUntil=0;
  let dnsCheck:Promise<void>|undefined;
  async function checkDnsUpstreams():Promise<void>{
    if(Date.now()<dnsHealthyUntil)return;
    if(!dnsCheck)dnsCheck=(async()=>{
      for(const [upstream,name] of [[mapped,'www.youtube.com'],[direct,'example.org']] as const){
        const header=Buffer.alloc(12);header.writeUInt16BE(Math.floor(Math.random()*65536),0);
        header.writeUInt16BE(256,2);header.writeUInt16BE(1,4);
        const labels=name.split('.').map(label=>Buffer.concat([Buffer.from([label.length]),Buffer.from(label)]));
        const query=Buffer.concat([header,...labels,Buffer.from([0,0,1,0,1])]);
        const answer=Buffer.from(await queryVerifiedDotTls(upstream,query,2500));
        if(answer.length<12||(answer[3]&15)!==0||answer.readUInt16BE(6)===0)
          throw Error('DNS upstream unhealthy');
      }
      dnsHealthyUntil=Date.now()+5000;
    })().finally(()=>{dnsCheck=undefined;});
    await dnsCheck;
  }
'''
 assert s.count(anchor)==1 and "      await db.query('SELECT 1');" in s
 s=s.replace(anchor,helper+anchor).replace("      await db.query('SELECT 1');","      await db.query('SELECT 1');\n      await checkDnsUpstreams();")
 changes[production]=(old,s)
 for p in changes:shutil.copy2(p,ROOT/p.name)
 rollback=ROOT/'rollback.sh';rollback.write_text('#!/bin/bash\nset -eu\n'+''.join('cat '+str(ROOT/p.name)+' > '+str(p)+'\n' for p in changes)+'docker restart '+C+' >/dev/null\n');rollback.chmod(0o700)
 timer='mnebydns-personal-fix-revert-'+str(os.getpid());run(['systemd-run','--quiet','--unit='+timer,'--on-active=4m','bash',str(rollback)])
 for p,(_,s) in changes.items():p.write_text(s)
 applied=True
 for path in ['/run/mnebydns-personal/personal-dot-production.ts','/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts']:
  run(['docker','exec',C,'node','--experimental-strip-types','--check',path])
 run(['docker','restart',C]);time.sleep(4)
 code="const h=require('http');h.get({host:'127.0.0.1',port:process.env.MNEBYDNS_PERSONAL_DOT_HEALTH_PORT||8855,path:'/readyz'},r=>{r.resume();r.on('end',()=>process.exit(r.statusCode===200?0:1));}).on('error',()=>process.exit(1));"
 for _ in range(3):run(['docker','exec',C,'node','-e',code]);time.sleep(1)
 run(['systemctl','stop',timer+'.timer'])
 print(json.dumps({'ok':True,'container':C,'backup':str(ROOT),'changes':['DNS upstream health probes','fallback time budget 4000/2500/10000ms','sanitized request failure and queue overflow logs'],'ready_checks':3}))
except Exception as e:
 if applied:
  for p,(old,_) in changes.items():p.write_text(old)
  subprocess.run(['docker','restart',C],capture_output=True,timeout=45)
 print(json.dumps({'ok':False,'error':str(e),'rolled_back':applied,'backup':str(ROOT)}));raise SystemExit(1)
